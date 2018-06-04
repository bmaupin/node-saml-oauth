const express = require('express');
const fs = require('fs');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

let myStrategy = new SamlStrategy(
  {
    path: '/login/callback',
    host: process.env.HOST || 'localhost',
    entryPoint: process.env.SAML_ENTRY_POINT || 'https://192.168.56.102:8443/auth/realms/master/protocol/saml',
    issuer: 'passport-saml',
    cert: process.env.SAML_CERT || null,
    privateCert: fs.readFileSync('./credentials/key.pem', 'utf-8'),
    decryptionPvk: fs.readFileSync('./credentials/key.pem', 'utf-8'),
  },
  function(profile, done) {
    profile.assertionXml = profile.getAssertionXml();
    done(null, profile);
  }
);

passport.use(myStrategy);

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
  });

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  }
);

// TODO: This only logs out of the app, not the IdP
app.get('/logout',
  function(req, res) {
    req.logout();
    res.redirect('/');
  }
);

app.get('/metadata',
  function(req, res) {
    const decryptionCert = fs.readFileSync('./credentials/cert.pem', 'utf-8');
    res.type('application/xml');
    res.send((myStrategy.generateServiceProviderMetadata(decryptionCert)));
  }
);

app.listen(process.env.PORT || 8080, '0.0.0.0');
