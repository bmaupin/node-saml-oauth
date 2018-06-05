const express = require('express');
const fs = require('fs');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2').Strategy;
const SamlStrategy = require('passport-saml').Strategy;

// This is to ignore self signed certificate error for OAuth 2
require('https').globalAgent.options.rejectUnauthorized = false;

const host = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000;

let samlStrategy = new SamlStrategy(
  {
    path: '/saml/login/callback',
    host: `${host}:${port}`,
    entryPoint: process.env.SAML_ENTRY_POINT || 'https://192.168.56.102:8443/auth/realms/master/protocol/saml',
    issuer: 'passport-saml',
    cert: process.env.SAML_CERT || null,
    privateCert: fs.readFileSync('./credentials/key.pem', 'utf-8'),
    decryptionPvk: fs.readFileSync('./credentials/key.pem', 'utf-8'),
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
    authorizationURL: 'https://192.168.56.102:8443/auth/realms/master/protocol/openid-connect/auth',
    tokenURL: 'https://192.168.56.102:8443/auth/realms/master/protocol/openid-connect/token',
    clientID: process.env.OAUTH_CLIENT_ID || null,
    clientSecret: process.env.OAUTH_CLIENT_SECRET || null,
    callbackURL: `http://${host}:${port}/oauth2/authorize/callback`,
    passReqToCallback: true,
  },
  function(req, accessToken, refreshToken, params, profile, done) {
    // Reuse the existing user from the SAML login
    let user = req.user;
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

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Define routes
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  }
);

// TODO: This only logs out of the app, not the IdP
app.get('/logout',
  function(req, res) {
    req.logout();
    res.redirect('/');
  }
);

app.get('/oauth2/authorize',
  passport.authenticate('oauth2')
);

app.get('/oauth2/authorize/callback',
  passport.authenticate('oauth2', { failureRedirect: '/' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  }
);

app.get('/saml/login',
  passport.authenticate('saml', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/saml/login/callback',
  passport.authenticate('saml', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/oauth2/authorize');
  }
);

app.get('/saml/metadata',
  function(req, res) {
    const decryptionCert = fs.readFileSync('./credentials/cert.pem', 'utf-8');
    res.type('application/xml');
    res.send((samlStrategy.generateServiceProviderMetadata(decryptionCert)));
  }
);

app.listen(port, '0.0.0.0');
