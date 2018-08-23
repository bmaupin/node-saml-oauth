const express = require('express');
const passport = require('passport');
const path = require('path');
const request = require('request');
const url = require('url');
const OAuth2Strategy = require('passport-oauth2').Strategy;
const SamlStrategy = require('passport-saml').Strategy;

const port = process.env.PORT || 3000;
const callbackBaseUrl = process.env.CALLBACK_BASE_URL || `http://localhost:${port}/`;
let samlSpKey = null;
if (typeof process.env.SAML_SP_KEY !== 'undefined') {
  samlSpKey = `-----BEGIN PRIVATE KEY-----\n${process.env.SAML_SP_KEY}\n-----END PRIVATE KEY-----`;
}

// This is to ignore self signed certificate error for OAuth 2
require('https').globalAgent.options.rejectUnauthorized = false;

let samlStrategy = new SamlStrategy(
  {
    callbackUrl: url.resolve(callbackBaseUrl, 'saml/login/callback'),
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: 'passport-saml',
    cert: process.env.SAML_IDP_CERT || null,
    privateCert: samlSpKey,
    decryptionPvk: samlSpKey,
  },
  function(profile, done) {
    let user = {};
    user.saml = profile;
    user.saml.assertionXml = profile.getAssertionXml();
    done(null, user);
  }
);
passport.use(samlStrategy);

passport.use(new OAuth2Strategy(
  {
    authorizationURL: process.env.OAUTH_AUTH_URL,
    tokenURL: process.env.OAUTH_TOKEN_URL,
    clientID: process.env.OAUTH_CLIENT_ID || null,
    clientSecret: process.env.OAUTH_CLIENT_SECRET || null,
    callbackURL: url.resolve(callbackBaseUrl, 'oauth2/authorize/callback'),
    passReqToCallback: true,
  },
  function(req, accessToken, refreshToken, params, profile, done) {
    let user = {};
    if (typeof req.user !== 'undefined') {
      // Reuse the existing user from the SAML login
      user = req.user;
    }
    user.oauth2 = profile;
    user.oauth2.accessToken = accessToken;
    user.oauth2.params = params;
    user.oauth2.refreshToken = refreshToken;
    done(null, user);
  }
));

// Configure Passport authenticated session persistence
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Create a new Express application
let app = express();

// Configure view engine to render EJS templates
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including logging, parsing, and session handling
app.use(require('morgan')('combined'));
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(require('helmet')());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Define routes
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  }
);

app.get('/api/test', (req, res) => {
  // Adapted from https://stackoverflow.com/a/51047525/399105
  const options = {
    url: process.env.OAUTH_VALIDATION_URL,
    headers: {
      // Send the authorization header directly to the OAuth server
      Authorization: req.headers.authorization,
    },
  };

  request(options, (error, response, body) => {
    if (error) {
      res.status(500);
      res.json({ error: error.toString() });

    } else if (response.statusCode !== 200) {
      res.status(response.statusCode);
      if (body) {
        res.json(JSON.parse(body));
      }
      res.send();

    } else {
      res.json({ test: 'successful!' });
    }
  });
});

// TODO: This only logs out of the app, not the IdP
app.get('/logout',
  function(req, res) {
    req.logout();
    res.redirect(process.env.LOGOUT_URL || '/');
  }
);

app.get('/oauth2/authorize',
  passport.authenticate('oauth2')
);

app.get('/oauth2/authorize/callback',
  passport.authenticate('oauth2', { failureRedirect: '/' }),
  function(req, res) {
    const options = {
      url: url.resolve(callbackBaseUrl, '/api/test'),
      headers: {
        Authorization: `Bearer ${req.user.oauth2.accessToken}`,
      },
    };

    request(options, (error, response, body) => {
      req.user.api = {};

      if (error) {
        req.user.api.response = error.toString();
      } else {
        req.user.api.response = body.toString();
      }

      res.redirect('/');
    });
  }
);

app.get('/saml/login',
  passport.authenticate('saml')
);

app.post('/saml/login/callback',
  passport.authenticate('saml', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/oauth2/authorize');
  }
);

app.get('/saml/metadata',
  function(req, res) {
    let samlSpCert = null;
    if (typeof process.env.SAML_SP_CERT !== 'undefined') {
      samlSpCert = `-----BEGIN CERTIFICATE-----\n${process.env.SAML_SP_CERT}\n-----END CERTIFICATE-----`;
    }
    res.type('application/xml');
    res.send((samlStrategy.generateServiceProviderMetadata(samlSpCert)));
  }
);

app.listen(port, '0.0.0.0', () => console.log(`Listening on port ${port}`));
