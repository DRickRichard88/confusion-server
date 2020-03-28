//storing authentication functions here. mainly, passport strategies are built here.
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
//^^allows us to build strategy
//we still have to define verfication function on this strategy
const users = require('./models/users');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

const config = require('./config');

//for local strategy:
exports.local = passport.use(new LocalStrategy(users.authenticate()));
//using the authenticate function from passport-local-mongoose as the..
//..local authentication function for passport
passport.serializeUser(users.serializeUser());
passport.deserializeUser(users.deserializeUser());
//^^for enabling sessions. to serialize means to create a session,..
//..and to deserialize means to delete the session. we defined functions..
//..to be used for both(here we used functions from passport-local-mongoose)

//for jwt strategy:
//now defining a fn. that creates a token for a user (passed as param), and returns it
exports.getToken = (user) => {
  //to create a token, we use the jsonwebtoken module
  return jwt.sign(user,config.secretKey,{expiresIn:3600});
};

const opts = {};
/*^^defines from where in the request the token is to be extracted*/
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;
//exporting the passport strategy
exports.jwtPassport = passport.use(new JwtStrategy(opts,
  (jwt_payload, done) => {
    console.log('JWT payload',jwt_payload);
    users.findOne({_id: jwt_payload._id}, (err,user) => {
      if (err) {
        return done(err, false);
      }
      else if(user) {
        return done(null,user);
      }
      else {
        return done(null,false);
      }
    });
  }));
//exporting authentication function
exports.verifyUser = passport.authenticate('jwt',{session: false});

exports.verifyAdmin = (req, res, next) => {
  users.findOne({_id: req.user._id})
    .then((user) => {
      console.log("User: ", req.user);
      if (user.admin) {
        next();
      }
      else {
        err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
      }
    }, (err) => next(err))
    .catch((err) => next(err))
}
