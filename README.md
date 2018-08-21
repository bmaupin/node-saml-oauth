### Description

This is a minimal example of an application that connects to an auth server using SAML and OAuth 2. Ideally you should probably use OpenID Connect instead.

Built with:

- [Node.js](https://nodejs.org/)
- [Express](http://expressjs.com/)
- [Passport](http://www.passportjs.org/)

### Requirements

You will need a server that supports SAML and OAuth, for example [Keycloak](https://www.keycloak.org/) or [Gluu Server](https://www.gluu.org/).

The following environment variables must be defined:

- `OAUTH_AUTH_URL`: OAuth 2 authorization endpoint URL
    - As an example, for Keycloak this might be `https://hostname/auth/realms/master/protocol/openid-connect/auth`
- `OAUTH_TOKEN_URL`: OAuth 2 token endpoint URL
    - As an example, for Keycloak this might be `https://hostname/auth/realms/master/protocol/openid-connect/token`
- `OAUTH_VALIDATION_URL`: OAuth 2 token validation URL
    - As an example, for Keycloak this might be `https://hostname/auth/realms/master/protocol/openid-connect/userinfo`
- `SAML_ENTRY_POINT`: SAML IdP (Identity Provider) HTTP redirect binding URL
    - You can get this from the IdP metadata (look for `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`)
    - As an example, for Keycloak this might be `https://hostname/auth/realms/master/protocol/saml`

Optional environment variables:

- `CALLBACK_BASE_URL`: Public base URL of your application to be used for callbacks from the IdP/authorization server
    - Defaults to `http://localhost:${PORT}/`
- `LOGOUT_URL`: Logout URL for the IdP/authorization server
    - As an example, for Keycloak this might be `https://hostname/auth/realms/master/protocol/openid-connect/logout?redirect_uri=${CALLBACK_BASE_URL}/`
- `OAUTH_CLIENT_ID`: OAuth 2 client ID
- `OAUTH_CLIENT_SECRET`: OAuth 2 client secret
- `PORT`: Port the app will listen on
    - Defaults to `3000`
- `SAML_IDP_CERT`: SAML IdP certificate that will be used to verify signatures of incoming SAML responses
    - The `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines should be stripped out
- `SAML_SP_CERT`: SSL cert that will be exposed in SAML metadata
    - The `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines should be stripped out
    - Note: if `SAML_SP_CERT` is defined, `SAML_SP_KEY` must also be defined.
- `SAML_SP_KEY`: SSL key that will be used to sign outgoing SAML requests and decrypt incoming SAML responses
    - The `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` lines should be stripped out
    - Note: if `SAML_SP_KEY` is defined, `SAML_SP_CERT` must also be defined.
