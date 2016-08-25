var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var OAuth2Strategy = require('passport-oauth2').Strategy;
var request = require('request');
var db = require('./db');


// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use(new LocalStrategy(
  function(username, password, cb) {
    db.users.findByUsername(username, function (err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      if (user.password != password) { return cb(null, false); }
      return cb(null, user);
    });
  }
));

var oauth2 = new OAuth2Strategy({
    authorizationURL: 'http://localhost:3000/oauth2/authorize',
    tokenURL: 'http://localhost:3000/oauth2/token',
    clientID: 'abc123',
    clientSecret: 'ssh-secret',
    callbackURL: "http://localhost:3001/auth/callback"
  },
  function (accessToken, refreshToken, profile, cb) {
    db.users.findOrCreate({
      displayName: profile.name,
      authUserId: profile.user_id
    }, function (err, user) {
      return cb(err, user);
    });
  }
);

passport.use(oauth2);

oauth2.userProfile = function (accessToken, done) {
  request('http://localhost:3000/api/userinfo', {json: true}, function (err, response, body) {
    console.log('uuuuuu', body, typeof body);
    done(null, body);
  }).auth(null, null, true, accessToken);
};

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.
passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  db.users.findById(id, function (err, user) {
    if (err) { return cb(err); }
    cb(null, user);
  });
});




// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

// Define routes.
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  });

// app.get('/login',
//   function(req, res){
//     res.render('login');
//   });

app.get('/login', passport.authenticate('oauth2'));

// app.post('/login', 
//   passport.authenticate('local', { failureRedirect: '/login' }),
//   function(req, res) {
//     res.redirect('/');
//   });
  
app.get('/logout',
  function(req, res){
    req.logout();
    res.redirect('/');
  });

app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  function(req, res){
    console.log('uuuuuuu', req.user);
    res.render('profile', { user: req.user });
  });

// app.get('/auth/example',
//   passport.authenticate('oauth2'));

app.get('/auth/callback',
  passport.authenticate('oauth2', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });

app.listen(3001);
