const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const flash = require('connect-flash');

const passport = require('passport');
const Strategy = require('passport-local').Strategy;
const session = require('express-session');
const md5 = require('md5');
const jwt = require('jsonwebtoken');

const User = require('./models/User');

const PORT = 8080;
const DB = 'auth';

mongoose.connect(`mongodb://localhost:27017/${DB}`, { useNewUrlParser: true });

const db = mongoose.connection;

db.on('error', function(err) {
  console.log(err);
});

db.once('open', function() {
  console.log('connection opened');
});

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(flash());

app.use(session({ secret: 'keyboard cat' }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new Strategy(
  function(username, password, done) {
    try {
      User.findOne({ username }).exec((err, data) => {
        const hashPassword = md5(password);
        const user = data;
        if (!err && hashPassword == user.password){
          const secret = 'secret';
          const token = jwt.sign(username, secret);
          console.log('token',token);
          const dataWithToken = Object.assign({ token }, { username });
          return done(null, dataWithToken);
        } else {
          return done(null, false);
        }
      });
    } catch(err) {
      console.log(err);
    }
  }
));

app.use('/auth', function(req, res, next) {
  const token = req.body.token;
  const secret = 'secret';
  if (token) {
    jwt.verify(token, secret, function (err, decoded) {
      if (err) {
          res.status(403).send({ message: 'User not authenticated' });
        } else {
          User.findOne({ username: decoded }).exec((err, data) => {
            if (err) {
              res.status(500).send({ err });
            }
            if (data) {
              res.status(200).send({ data });
            } else {
              res.send(err);
             }
         });
      }
  });
  } else {
     res.status(403).send({ message: 'Token not provided' });
  }
});

const passportConfig = { session: false };

app.post('/login', passport.authenticate('local', passportConfig), function (req, res) {
  res.json({ user: req.user });
});

app.post('/register', function(req, res) {
  const { username, password } = req.body;
  User.find({ username }, function (err, docs) {
    if (!docs.length) {
      var newUser = new User({ username, password: md5(password) });
      newUser.save(function (err) {
        if (err) {
          return res.json({ message: 'That username already exists.' });
        }
        res.json({ message: 'Successfully created new user.' });
      });
    } else {
      return res.json({ message: 'That username already exists.' });
    }
  });
});

app.listen(PORT, function () {
  console.log(`Example app listening on port ${PORT}!`);
});
