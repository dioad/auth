# Browser session

A minimal single-page app and API protected by a browser session. Users sign
in with OIDC. The server keeps the tokens in encrypted cookies and gives the
page no token to handle: this is the backend-for-frontend (BFF) pattern, from
[`http/browsersession`](../../http/browsersession).

`ExampleNewApp` in that package runs the same wiring against a mock provider.
The code here is in [main.go](main.go) and [static/index.html](static/index.html).

## Routes

| Route | Served by |
|---|---|
| `GET /auth/login` | redirects to the provider |
| `GET /auth/callback` | completes login and sets the session cookies |
| `POST /auth/logout` | ends the session |
| `GET /auth/config` | the issuer and client ID |
| `GET /api/me` | the API, behind the session |
| everything else | the single-page app; a browser without a session is sent to `/auth/login` |

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `OIDC_ISSUER` | the OIDC issuer URL | required |
| `OIDC_CLIENT_ID` | the client registered with the provider | required |
| `OIDC_CLIENT_SECRET` | its secret | required |
| `OIDC_REDIRECT_URI` | the callback URL registered with the provider | `http://127.0.0.1:8080/auth/callback` |
| `COOKIE_ENCRYPTION_KEY` | 64 hexadecimal characters; `openssl rand -hex 32` | required |
| `LISTEN_ADDR` | address to listen on | `127.0.0.1:8080` |

Register `OIDC_REDIRECT_URI` with the provider and allow the client's
audience, which this example sets to the client ID. Changing
`COOKIE_ENCRYPTION_KEY` signs every user out.

```bash
export OIDC_ISSUER=https://idp.example/realms/demo OIDC_CLIENT_ID=demo OIDC_CLIENT_SECRET=...
export COOKIE_ENCRYPTION_KEY=$(openssl rand -hex 32)
go run ./examples/browser-session
```

Open `http://127.0.0.1:8080/`. The cookies are `Secure`. Browsers still
accept them over plain HTTP on `127.0.0.1`, but not on other hosts.

## Cookie and CSRF model

- **Encrypted.** The access token, refresh token and expiry are each stored in
  their own AES-256-GCM encrypted cookie. A cookie is bound to its name, so a
  value cannot be moved from one cookie to another.
- **HttpOnly, Secure, SameSite=Lax.** The page's JavaScript cannot read them,
  and the browser does not send them on a cross-site `POST`, `PUT`, `PATCH` or
  `DELETE`. Do not make a state-changing API route answer a `GET`.
- **Not a bearer token.** The session cookies are named `bff_session`,
  `bff_refresh` and `bff_expiry`. A JWT middleware does not read them, and
  their values are ciphertext. On each API request the server decrypts the
  access token and sets the `Authorization` header, so the API validates it as
  it would any bearer token. A request that arrives with an `Authorization`
  header of its own is refused.
- **Refresh.** A session that expires within five minutes is refreshed on the
  way through, and the new tokens are written back to the cookies. If the
  refresh fails, the session is cleared.
- **Logout.** `POST` only, and it does nothing without a session cookie: a
  cross-site request carries none, so another site cannot sign a user out. When
  there is a session, the provider session is ended too, so the next login is
  not automatic.
- **Authorization is the API's job.** The session proves who signed in. The API
  still validates the token and decides what the caller may do.
