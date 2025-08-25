export default class OAuth2Client {
    constructor(config) {
        this.user = null;
        this.bffUrl = config.bffUrl ? config.bffUrl.replace(/\/$/, "") : "";
        this.paths = config.paths || { auth: "/auth", api: "/api" };
        this.checkAuth();
    }
    getUser() {
        return this.user;
    }
    isAuthenticated() {
        return this.user !== null;
    }
    async checkAuth() {
        try {
            const response = await fetch(`${this.bffUrl}${this.paths.auth}/check-session`, {
                credentials: "include"
            });
            if (response.ok) {
                const data = await response.json();
                this.user = data.authenticated ? data.userInfo : null;
                return this.user;
            }
            this.user = null;
            return null;
        }
        catch (error) {
            this.user = null;
            return null;
        }
    }
    async login(usePopup = false) {
        if (usePopup) {
            const user = await this.loginPopup();
            this.user = user;
            return user;
        }
        else {
            window.location.href = `${this.bffUrl}${this.paths.auth}/login`;
        }
    }
    loginPopup() {
        return new Promise((resolve, reject) => {
            const popup = window.open(`${this.bffUrl}${this.paths.auth}/login?popup=true`, "oauth-login", "width=500,height=600,scrollbars=yes,resizable=yes");
            if (!popup)
                return reject(new Error("Failed to open popup"));
            const messageHandler = (event) => {
                const expectedOrigin = this.bffUrl ? new URL(this.bffUrl).origin : window.location.origin;
                if (event.origin !== expectedOrigin)
                    return;
                if (event.source !== popup)
                    return;
                window.removeEventListener("message", messageHandler);
                clearInterval(checkClosed);
                clearTimeout(timeoutHandler);
                popup.close();
                if (event.data.type === "oauth_success") {
                    resolve(event.data.userInfo || true);
                }
                else if (event.data.type === "oauth_error") {
                    reject(new Error(event.data.error || "Login failed"));
                }
                else {
                    reject(new Error("Invalid response from login"));
                }
            };
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    clearTimeout(timeoutHandler);
                    window.removeEventListener("message", messageHandler);
                    reject(new Error("Login cancelled"));
                }
            }, 1000);
            const timeoutHandler = setTimeout(() => {
                if (!popup.closed) {
                    popup.close();
                    window.removeEventListener("message", messageHandler);
                    clearInterval(checkClosed);
                    reject(new Error("Login timeout"));
                }
            }, 300000);
            window.addEventListener("message", messageHandler);
        });
    }
    async logout() {
        try {
            await fetch(`${this.bffUrl}${this.paths.auth}/logout`, {
                method: "POST",
                credentials: "include",
                headers: {
                    "X-CSRF-Token": "1",
                }
            });
        }
        catch (error) {
            console.log("something went wrong, logging out", error);
        }
        this.user = null;
    }
    async callApi(path, options = {}) {
        const url = `${this.bffUrl}${this.paths.api}${path}`;
        console.log("Calling API:", url, options);
        const response = await fetch(url, {
            ...options,
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": "1",
                ...options.headers
            }
        });
        if (response.status === 401)
            await this.checkAuth();
        return response;
    }
}
