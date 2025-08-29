export interface Config {
    clientId: string;
    authServer: string;
    scope?: string;
    redirectUri?: string;
    successUri?: string;
    services?: Record<string, string>;
    publicRoutes?: string[];
    refreshTokenLifetime?: number;
    debug?: boolean;
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
export interface SessionStore {
    set(key: string, value: SessionData, ttlMs?: number): Promise<void>;
    get(key: string): Promise<SessionData | null>;
    delete(key: string): Promise<void>;
}
export default class OAuth2Server {
    private config;
    private sessionStore;
    private sessionCookieName;
    constructor(config: Config, sessionStore?: SessionStore);
    private generateCode;
    private sha256;
    private setSessionCookie;
    login(request: Request): Promise<Response>;
    private getTokens;
    private decodeIdToken;
    private getSessionId;
    private log;
    private err;
    callback(request: Request): Promise<Response>;
    logout(request: Request): Promise<Response>;
    private refresh;
    fetchApi(request: Request): Promise<Response>;
    private isPathSafe;
    private sanitizeHeaders;
    private makeRequest;
    checkSession(request: Request): Promise<Response>;
}
export {};
