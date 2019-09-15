# Authorizer

The authorizer is an SPNEGO-enabled web service.

All endpoints are authenticated by SPNEGO.

It serves two endpoints:
- `/` redirects user to Google OAuth 2.0 Login
- `/oauth2callback` accepts OAuth 2.0 authorization token, uses it to obtain a Refresh Token for the authenticated user. The Refresh Token is encrypted and stored in the database.


# Settings

- `AUTHORIZER_HOST` bind address
- `AUTHORIZER_PORT` listen port
- `AUTHORIZER_KEYTAB` path to keytab containing login principal
- `AUTHORIZER_PRINCIPAL` Kerberos principal name in format `HTTP/host.domain.tld@REALM`
- `OAUTH_CALLBACK_URI` callback URI where authorization token is accepted after login.
- `OAUTH_CLIENT_ID` OAuth 2.0 Client ID obtained from Cloud Console by creating an OAuth 2.0 application. Used to request Access Tokens.
- `OAUTH_CLIENT_SECRET` OAuth 2.0 Client Secret obtained from Cloud Console by creating an OAuth 2.0 application. Used to request Access Tokens.
- `AUTHORIZER_ENABLE_SPNEGO` boolean value indicating whether to require SPNEGO. Default: "true"


## Required Settings from other modules

- `DATABASE_BACKEND` Default: JDBCBackend
- `DATABASE_JDBC_URL` JDBC URL in format `jdbc:dialect:...`
- `ENCRYPTION_BACKEND` The authorizer encrypts all refresh tokens before storing them in the database.