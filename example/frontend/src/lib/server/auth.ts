import OAuth2Server from 'sjallabong-auth';

export const oauth = new OAuth2Server({
    clientId: 'chattabong',
    authServer: 'http://localhost:3001',
    redirectUri: 'http://localhost:5173/auth/callback',
    services: {
        "/test": "http://localhost:3002"
    },
    debug: true
});