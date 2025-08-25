export default class OAuth2Client {
    private bffUrl;
    private user;
    private paths;
    constructor(config: {
        bffUrl?: string;
        paths?: {
            auth: string;
            api: string;
        };
    });
    getUser(): any;
    isAuthenticated(): boolean;
    checkAuth(): Promise<any>;
    login(usePopup?: boolean): Promise<any>;
    private loginPopup;
    logout(): Promise<void>;
    callApi(path: string, options?: RequestInit): Promise<Response>;
}
