export interface Config {
    clientId: string;
    authServer: string;
    scope?: string;
    redirectUri?: string;
    successUri?: string;
    services?: Record<string, string>;
}

interface TokenResponse {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    expires_in: number;
    // token_type: string;
}

interface SessionData {
    accessToken: string;
    refreshToken?: string;
    expiresAt: number;
    codeVerifier?: string;
    state?: string;
    isPopup?: boolean;
    userInfo?: any;
}

// let clients use their own caches
export interface SessionStore {
    set(key: string, value: SessionData, ttlMs?: number): Promise<void>;
    get(key: string): Promise<SessionData | null>;
    delete(key: string): Promise<void>;
}
// todo session mgmt, cleanup, invalidation, etc

class DevSessionStore implements SessionStore {
    private store = new Map<string, { data: SessionData; expires: number }>();

    async set(key: string, value: SessionData, ttlMs = 600000): Promise<void> {
        this.store.set(key, {
            data: value,
            expires: Date.now() + ttlMs
        });
    }

    async get(key: string): Promise<SessionData | null> {
        const entry = this.store.get(key);
        if (!entry || entry.expires < Date.now()) {
            this.store.delete(key);
            return null;
        }
        return entry.data;
    }

    async delete(key: string): Promise<void> {
        this.store.delete(key);
    }
}

export default class OAuth2Server {
    private config: Required<Config>;
    private sessionStore: SessionStore;

    constructor(config: Config, sessionStore?: SessionStore) {
        if (!config?.clientId) throw new Error("Client ID is required");
        if (!config?.authServer) throw new Error("Auth server URL is required");

        this.config = {
            clientId: config.clientId,
            authServer: config.authServer,
            scope: config.scope || "openid profile", // maybe these should be explicitly set
            redirectUri: config.redirectUri || `${config.authServer}/success`,
            successUri: config.successUri || "/",
            services: config.services || {},
        };

        this.sessionStore = sessionStore || new DevSessionStore();
    }

    private generateCode(length: number): string {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    private async sha256(text: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hash = await crypto.subtle.digest("SHA-256", data);
        return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    private setSessionCookie(sessionId: string, maxAgeSeconds: number): string {
        return `session_id=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;
    }

    async login(request: Request): Promise<Response> {
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
                expiresAt: Date.now() + 600000
            }, 600000);

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
                    "Set-Cookie": this.setSessionCookie(sessionId, 600)
                }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: "Login initiation failed" }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    private async getTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
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
            throw new Error(`Token exchange failed: ${errorText}`);
        }

        return await response.json();
    }

    private decodeIdToken(idToken: string): any {
        const payload = idToken.split(".")[1];
        const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
        return JSON.parse(decoded);
    }

    private getSessionId(request: Request): string | null {
        const cookies = request.headers.get("cookie");
        if (!cookies) return null;

        const sessionMatch = cookies.match(/session_id=([^;]+)/);
        if (!sessionMatch) return null;

        return sessionMatch[1];
    }

    async callback(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url);
            const auth_code = url.searchParams.get("code");
            const state = url.searchParams.get("state");
            const error = url.searchParams.get("error");

            if (error) return new Response(null, { status: 302, headers: { "Location": `${this.config.redirectUri}?error=${error}` } });
            if (!auth_code || !state) return new Response("Missing authorization code or state", { status: 400 });

            const sessionId = this.getSessionId(request);
            if (!sessionId) return new Response("Invalid session", { status: 400 });
            const session = await this.sessionStore.get(sessionId);
            if (!session) return new Response("Invalid session", { status: 400 });
            if (session.state !== state) return new Response("State mismatch", { status: 400 });
            if (!session.codeVerifier) return new Response("Missing code verifier", { status: 400 });

            // authorization code -> tokens
            const tokens = await this.getTokens(auth_code, session.codeVerifier);
            session.accessToken = tokens.access_token;
            session.refreshToken = tokens.refresh_token;
            session.expiresAt = Date.now() + (tokens.expires_in * 1000);
            if (tokens.id_token) {
                session.userInfo = this.decodeIdToken(tokens.id_token);
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

            // 30 days per auth server (todo move out)?
            const maxAge = 30 * 24 * 60 * 60;
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": this.config.successUri,
                    "Set-Cookie": this.setSessionCookie(sessionId, maxAge)
                }
            });
        } catch (error) {
            console.error("Callback error:", error);
            return new Response(JSON.stringify({ error: "Authentication failed" }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async logout(request: Request): Promise<Response> {
        if (!request.headers.get('X-CSRF-Token')) return new Response("Forbidden", { status: 403 });
        const sessionId = this.getSessionId(request);
        if (sessionId) await this.sessionStore.delete(sessionId);
        return new Response(null, {
            status: 204, // rare 204
            headers: {
                "Set-Cookie": this.setSessionCookie("", 0)
            }
        });
    }

    private async refresh(session: SessionData): Promise<void> {
        const response = await fetch(`${this.config.authServer}/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: this.config.clientId,
                refresh_token: session.refreshToken!
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Refresh token exchange failed: ${response.status} - ${errorText}`);
        }

        const tokens = await response.json();
        session.accessToken = tokens.access_token;
        session.refreshToken = tokens.refresh_token;
        session.expiresAt = Date.now() + (tokens.expires_in * 1000);
    }

    // bff proxy
    async fetchApi(request: Request): Promise<Response> {
        if (request.method !== 'GET' && !request.headers.get('X-CSRF-Token')) return new Response("Forbidden", { status: 403 });

        const sessionId = this.getSessionId(request);
        if (!sessionId) return new Response("No session", { status: 401 });

        const session = await this.sessionStore.get(sessionId);
        if (!session?.accessToken) return new Response("Unauthorized", { status: 401 });

        // try initial request with access
        let response = await this.makeRequest(request, session.accessToken);
        if (response.status === 401 && session.refreshToken) {
            try {
                await this.refresh(session);
                await this.sessionStore.set(sessionId, session);
                response = await this.makeRequest(request, session.accessToken);
            } catch (error) {
                return new Response("Unauthorized", { status: 401 });
            }
        }

        return response;
    }

    private async makeRequest(request: Request, accessToken: string): Promise<Response> {
        const url = new URL(request.url);
        console.log("got url:", url);
        console.log("Configured services:", this.config.services);
        const servicePath = Object.keys(this.config.services).find(path => url.pathname.startsWith(path));
        if (!servicePath) return new Response("Service not found", { status: 404 });
        console.log("Matched service path:", servicePath);

        // path traversal
        const baseUrl = this.config.services[servicePath].replace(/\/$/, "");
        const targetUrl = `${baseUrl}${url.pathname.slice(servicePath.length)}`;
        if (!targetUrl.startsWith(baseUrl + "/") && targetUrl !== baseUrl) return new Response("Invalid target", { status: 400 });
        console.log("Proxying to:", targetUrl);

        const proxyHeaders = new Headers(request.headers);
        proxyHeaders.delete("cookie");
        proxyHeaders.delete("X-CSRF-Token");
        proxyHeaders.set("Authorization", `Bearer ${accessToken}`);

        console.log("Proxying request to:", targetUrl, request.method, proxyHeaders);
        console.log("final url:", targetUrl + url.search);

        return fetch(targetUrl + url.search, {
            method: request.method,
            headers: proxyHeaders,
            body: request.body
        });
    }

    // authenticated: bool, userInfo: object|null
    async checkSession(request: Request): Promise<Response> {
        const sessionId = this.getSessionId(request);
        const session = sessionId ? await this.sessionStore.get(sessionId) : null;

        if (session?.accessToken && session.expiresAt > Date.now()) {
            return new Response(JSON.stringify({
                authenticated: true,
                userInfo: session.userInfo
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        return new Response(JSON.stringify({ authenticated: false }), {
            headers: { "Content-Type": "application/json" }
        });
    }
}