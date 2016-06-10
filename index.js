var express = require('express'),
exphbs = require('express-handlebars'),
logger = require('morgan'),
cookieParser = require('cookie-parser'),
bodyParser = require('body-parser'),
methodOverride = require('method-override'),
session = require('express-session'),
passport = require('passport'),
LocalStrategy = require('passport-local'),
TwitterStrategy = require('passport-twitter'),
GoogleStrategy = require('passport-google'),
FacebookStrategy = require('passport-facebook'),
crypto = require('crypto');

var config = require('./config.js'), 
funct = require('./functions.js'); 
var app = express();


passport.serializeUser(function(user, done) {
  console.log("serializing " + user.username);
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  console.log("deserializing " + obj);
  done(null, obj);
});

passport.use('local-signin', new LocalStrategy(
  {passReqToCallback : true}, 
  function(req, username, password, done) {
    funct.localAuth(username, password)
    .then(function (user) {
      if (user) {

        //===============SECURE MODE================

        var hmac = crypto.createHmac('sha256', '4fd9ecd38ea20527ccf5be8ac120d588');
        hmac.update(user.username);
        signature = hmac.digest('hex');
        console.log('================')
        console.log(signature)
        console.log('================')
        app.locals.data = {signature: signature};
        
        //===========================================

        console.log("LOGGED IN AS: " + user.username);
        req.session.success = 'You are successfully logged in ' + user.username + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT LOG IN");
        req.session.error = 'Could not log user in. Please try again.'; 
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });

  }
  ));

 

passport.use('local-signup', new LocalStrategy(
  {usernameField: 'email', passReqToCallback : true}, 
  function(req, username, password, done) {
    funct.localReg(username, password)
    .then(function (user) {
      if (user) {
        var hmac = crypto.createHmac('sha256', '70ccf7c72278011666f04368c68e940f');
        hmac.update(user.username);
        signature = hmac.digest('hex');
        app.locals.data = {signature: signature};
        console.log("REGISTERED: " + user.username);
        req.session.success = 'You are successfully registered and logged in ' + user.username + '!';
        done(null, user);
      }
      if (!user) {
        console.log("COULD NOT REGISTER");
        req.session.error = 'That username is already in use, please try a different one.'; 
        done(null, user);
      }
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
  ));

//===============EXPRESS================

app.use(logger('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(methodOverride('X-HTTP-Method-Override'));
app.use(session({secret: 'supernova', saveUninitialized: true, resave: true}));
app.use(passport.initialize());
app.use(passport.session());


app.use(function(req, res, next){
  var err = req.session.error,
  msg = req.session.notice,
  success = req.session.success;

  delete req.session.error;
  delete req.session.success;
  delete req.session.notice;

  if (err) res.locals.error = err;
  if (msg) res.locals.notice = msg;
  if (success) res.locals.success = success;

  next();
});


var hbs = exphbs.create({
  defaultLayout: 'main', 
});
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

//===============ROUTES===============

app.get('/', function(req, res){
  res.render('home', {user: req.user});
});


app.get('/signin', function(req, res){
  res.render('signin');
});


app.post('/local-reg', passport.authenticate('local-signup', {
  successRedirect: '/',
  failureRedirect: '/signin'
})
);


app.post('/login', passport.authenticate('local-signin', {
  successRedirect: '/',
  failureRedirect: '/signin'
})
);


app.get('/logout', function(req, res){
  var name = req.user.username;
  console.log("LOGGIN OUT " + req.user.username)
  req.logout();
  res.redirect('/');
  req.session.notice = "You have successfully been logged out " + name + "!";
});

//===============PORT=================
var port = process.env.PORT || 5000; 
app.listen(port);
console.log("listening on " + port + "!");