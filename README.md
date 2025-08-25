# sjallabong-auth

OAuth2 BFF PKCE library for [Sjallabong Auth](https://gitlab.com/sjallabong/auth).

## Installation
```sh
npm install sjallabong-auth
```

## Setup
### Server
```js
import OAuth2Server from 'sjallabong-auth';

const oauth = new OAuth2Server({
    clientId: 'some-client-id',
    authServer: 'https://auth.sjallabong.eu',
    services: {
        "/resources": "https://example.com"
    }
});
```

### Frontend
```js
import OAuth2Client from 'sjallabong-auth/client';

const auth = new OAuth2Client({});

await auth.login() // basically
```


