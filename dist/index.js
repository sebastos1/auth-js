import { parse, serialize } from "cookie";
import { jwtVerify, createRemoteJWKSet } from 'jose';
// todo: rate limiting considerations
// not handling expiration here, if you use this in production you deserve what you get
class DevSessionStore {
    store = new Map();
    async set(key, value, ttlMs) {
        this.store.set(key, {
            data: value,
            expires: Date.now() + ttlMs
        });
    }
    async get(key) {
        const entry = this.store.get(key);
        if (!entry || entry.expires < Date.now()) {
            this.store.delete(key);
            return null;
        }
        return entry.data;
    }
    async delete(key) {
        this.store.delete(key);
    }
}
export default class OAuth2Server {
    config;
    sessionStore;
    sessionCookieName = "session_id";
    jwks;
    constructor(config, sessionStore) {
        if (!config?.clientId)
            throw new Error("Client ID is required");
        if (!config?.authServer)
            throw new Error("Auth server URL is required");
        this.config = {
            clientId: config.clientId,
            authServer: config.authServer,
            scope: config.scope || "openid profile", // maybe these should be explicitly set
            redirectUri: config.redirectUri || `${config.authServer}/success`,
            successUri: config.successUri || "/",
            services: config.services || {},
            publicRoutes: config.publicRoutes || [],
            refreshTokenLifetime: config.refreshTokenLifetime || (30 * 24 * 60 * 60), // 30 days,
            debug: config.debug || false
        };
        if (!this.config.debug) {
            this.sessionCookieName = "__Host-session_id"; // todo ?
        }
        this.sessionStore = sessionStore || new DevSessionStore();
        this.jwks = createRemoteJWKSet(new URL(`${this.config.authServer}/.well-known/jwks.json`));
    }
    generateCode(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }
    async sha256(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hash = await crypto.subtle.digest("SHA-256", data);
        return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }
    setSessionCookie(sessionId, maxAgeSeconds) {
        return serialize(this.sessionCookieName, sessionId, {
            httpOnly: true,
            secure: !this.config.debug,
            sameSite: "strict",
            path: "/",
            maxAge: maxAgeSeconds,
            // domain?
        });
    }
    async login(request) {
        try {
            const codeVerifier = this.generateCode(32);
            const codeChallenge = await this.sha256(codeVerifier);
            const state = this.generateCode(16); // 16-32 recommended
            const url = new URL(request.url);
            const isPopup = url.searchParams.get("popup") === "true";
            // todo: store this somewhere, and clean old ones
            const sessionId = this.generateCode(32);
            this.sessionStore.set(sessionId, {
                accessToken: "",
                codeVerifier,
                state,
                isPopup,
                expiresAt: Date.now() + this.config.refreshTokenLifetime * 1000
            }, this.config.refreshTokenLifetime * 1000);
            const params = new URLSearchParams({
                client_id: this.config.clientId,
                redirect_uri: this.config.redirectUri,
                scope: this.config.scope,
                state: state,
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                response_type: "code"
            });
            const authUrl = `${this.config.authServer}/authorize?${params}`;
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": authUrl,
                    "Set-Cookie": this.setSessionCookie(sessionId, this.config.refreshTokenLifetime)
                }
            });
        }
        catch (error) {
            this.log("Login error:", error);
            return this.err(500, "Login initiation failed");
        }
    }
    async getTokens(code, codeVerifier) {
        const response = await fetch(`${this.config.authServer}/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: this.config.clientId,
                code,
                redirect_uri: this.config.redirectUri,
                code_verifier: codeVerifier
            })
        });
        if (!response.ok) {
            const errorText = await response.text();
            this.log("Token exchange failed:", response.status, errorText);
            throw new Error(`Token exchange failed: ${errorText}`);
        }
        return await response.json();
    }
    getSessionId(request) {
        const cookieHeader = request.headers.get("cookie");
        if (!cookieHeader)
            return null;
        const cookies = parse(cookieHeader);
        return cookies[this.sessionCookieName] || null;
    }
    log(...args) {
        const time = new Date().toISOString();
        if (this.config.debug)
            console.log(`[${time}]`, ...args);
    }
    err(status, message) {
        message = this.config.debug ? message : "Error";
        return new Response(JSON.stringify({ error: message }), {
            status,
            headers: { "Content-Type": "application/json" }
        });
    }
    async validateJwt(token) {
        try {
            const { payload } = await jwtVerify(token, this.jwks, {
                issuer: this.config.authServer,
                audience: this.config.clientId,
            });
            return payload;
        }
        catch (error) {
            this.log("Token validation failed:", error);
            throw error;
        }
    }
    async callback(request) {
        try {
            const url = new URL(request.url);
            const auth_code = url.searchParams.get("code");
            const state = url.searchParams.get("state");
            const error = url.searchParams.get("error");
            if (error)
                return new Response(null, { status: 302, headers: { "Location": `${this.config.redirectUri}?error=${error}` } });
            if (!auth_code || !state)
                return this.err(400, "Missing authorization code or state");
            const sessionId = this.getSessionId(request);
            if (!sessionId)
                return this.err(400, "Invalid session");
            const session = await this.sessionStore.get(sessionId);
            if (!session)
                return this.err(400, "Invalid session");
            if (session.state !== state)
                return this.err(400, "State mismatch");
            if (!session.codeVerifier)
                return this.err(400, "Missing code verifier");
            // authorization code -> tokens
            const tokens = await this.getTokens(auth_code, session.codeVerifier);
            if (tokens.access_token) {
                try {
                    await this.validateJwt(tokens.access_token);
                }
                catch (error) {
                    this.log("Invalid access token:", error);
                    return this.err(400, "Invalid access token");
                }
            }
            session.accessToken = tokens.access_token;
            session.refreshToken = tokens.refresh_token;
            session.expiresAt = Date.now() + (tokens.expires_in * 1000);
            if (tokens.id_token) {
                try {
                    const idTokenPayload = await this.validateJwt(tokens.id_token);
                    session.userInfo = idTokenPayload;
                }
                catch (error) {
                    this.log("Invalid ID token:", error);
                    return this.err(400, "Invalid ID token");
                }
            }
            const isPopup = session.isPopup || false;
            delete session.codeVerifier;
            delete session.state;
            delete session.isPopup;
            await this.sessionStore.set(sessionId, session);
            if (isPopup) {
                const script = `<script>
                    if (window.opener) {
                        window.opener.postMessage({
                            type: "oauth_success",
                            userInfo: ${JSON.stringify(session.userInfo || true)}
                        }, window.location.origin);
                    }
                    window.close();
                </script>`;
                return new Response(script, {
                    status: 200,
                    headers: { "Content-Type": "text/html" }
                });
            }
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": this.config.successUri,
                    "Set-Cookie": this.setSessionCookie(sessionId, this.config.refreshTokenLifetime)
                }
            });
        }
        catch (error) {
            this.log("Callback error:", error);
            return this.err(500, "Callback processing failed");
        }
    }
    async logout(request) {
        if (!request.headers.get("X-CSRF-Token"))
            return this.err(403, "Forbidden");
        const sessionId = this.getSessionId(request);
        if (sessionId)
            await this.sessionStore.delete(sessionId);
        return new Response(null, {
            status: 204, // rare 204
            headers: {
                "Set-Cookie": this.setSessionCookie("", 0)
            }
        });
    }
    async refresh(session, sessionId) {
        const response = await fetch(`${this.config.authServer}/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: this.config.clientId,
                refresh_token: session.refreshToken
            })
        });
        if (!response.ok) {
            this.log("Refresh token exchange failed:", response.status, await response.text());
            if (sessionId)
                await this.sessionStore.delete(sessionId);
            throw new Error(`Refresh token exchange failed: ${response.status}`);
        }
        const tokens = await response.json();
        Object.assign(session, {
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token || session.refreshToken, // keep old if not rotated
            expiresAt: Date.now() + (tokens.expires_in * 1000)
        });
    }
    // bff proxy
    async fetchApi(request) {
        if (request.method !== "GET" && !request.headers.get("X-CSRF-Token"))
            return this.err(403, "Forbidden");
        this.log("Fetch API request:", request.method, request.url);
        this.log("public routes: ", this.config.publicRoutes);
        const url = new URL(request.url);
        this.log("Request path:", url.pathname);
        const isPublicRoute = this.config.publicRoutes?.includes(url.pathname);
        this.log("Is public route:", isPublicRoute);
        if (isPublicRoute)
            return this.makeRequest(request, "");
        const sessionId = this.getSessionId(request);
        if (!sessionId) {
            this.log("No session ID found");
            return this.err(401, "No session");
        }
        const session = await this.sessionStore.get(sessionId);
        if (!session?.accessToken)
            return this.err(401, "No access token");
        // try initial request with access
        let response = await this.makeRequest(request, session.accessToken);
        if (response.status === 401 && session.refreshToken) {
            try {
                await this.refresh(session, sessionId);
                await this.sessionStore.set(sessionId, session);
                response = await this.makeRequest(request, session.accessToken);
            }
            catch (error) {
                this.log("Token refresh failed:", error);
                return this.err(401, "Session expired");
            }
        }
        return response;
    }
    isPathSafe(path) {
        try {
            path = decodeURIComponent(path);
        }
        catch {
            this.log("Failed to decode path:", path);
            return false;
        }
        try {
            const url = new URL(path, "http://localhost/"); // base needed, dw
            const normalizedPath = url.pathname;
            return !normalizedPath.includes("../") &&
                !normalizedPath.includes("..\\") &&
                normalizedPath.startsWith("/");
        }
        catch {
            this.log("Failed to parse path:", path);
            return false;
        }
    }
    sanitizeHeaders(headers) {
        const cleanHeaders = new Headers();
        const allowed = ["accept", "content-type"]; // todo?
        headers.forEach((value, key) => {
            if (allowed.includes(key.toLowerCase())) {
                cleanHeaders.set(key, value);
            }
        });
        return cleanHeaders;
    }
    async makeRequest(request, accessToken) {
        const url = new URL(request.url);
        const servicePath = Object.keys(this.config.services).find(path => url.pathname.startsWith(path));
        if (!servicePath)
            return this.err(404, "Unknown service");
        if (this.config.debug) {
            console.log("URL pathname:", url.pathname);
            console.log("Service paths:", Object.keys(this.config.services));
            console.log("Matched service path:", servicePath);
        }
        const requestPath = url.pathname.slice(servicePath.length);
        if (!this.isPathSafe(requestPath))
            return this.err(400, "Invalid path");
        const baseUrl = this.config.services[servicePath].replace(/\/$/, "");
        const targetUrl = `${baseUrl}${requestPath}`;
        const headers = this.sanitizeHeaders(request.headers);
        if (accessToken)
            headers.set("Authorization", `Bearer ${accessToken}`);
        headers.set("User-Agent", "Mozilla/5.0 (compatible; BFF-Proxy/1.0)");
        this.log("Proxying request to:", targetUrl + url.search, request.method);
        return fetch(targetUrl + url.search, {
            method: request.method,
            headers,
            body: request.body,
            duplex: "half"
        }); // bruh
    }
    // authenticated: bool, userInfo: object|null
    async checkSession(request) {
        const sessionId = this.getSessionId(request);
        const session = sessionId ? await this.sessionStore.get(sessionId) : null;
        if (session?.accessToken) {
            if (session.expiresAt > Date.now()) {
                return new Response(JSON.stringify({
                    authenticated: true,
                    userInfo: session.userInfo
                }), {
                    headers: { "Content-Type": "application/json" }
                });
            }
            else {
                if (sessionId)
                    await this.sessionStore.delete(sessionId);
            }
        }
        return new Response(JSON.stringify({ authenticated: false }), {
            headers: { "Content-Type": "application/json" }
        });
    }
}
