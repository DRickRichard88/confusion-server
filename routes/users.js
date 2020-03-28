const express = require("express");
const bodyParser = require("body-parser");
const user = require("../models/users");
const passport = require("passport");
const authenticate = require("../authenticate");

const router = express.Router();
router.use(bodyParser.json());

//getting all users' data. only an admin function.
router.get(
  "/",
  authenticate.verifyUser,
  authenticate.verifyAdmin,
  (req, res, next) => {
    user
      .find({})
      .then(
        users => res.status(200).json(users),
        err => next(err)
      )
      .catch(err => next(err));
  }
);

//signup route
router.post("/signup", (req, res, next) => {
  //using register function of passport-local-mongoose plugin:
  user.register(
    new user({ username: req.body.username }),
    req.body.password,
    (err, user) => {
      //this callback isn't returned in a promise, so we'll have to define it here itself
      if (err) res.status(500).json({ err: err });
      //handling error here
      else {
        //adding firstname and lastname (if passed in the request)
        if (req.body.firstname) user.firstname = req.body.firstname;
        if (req.body.lastname) user.lastname = req.body.lastname;
        user.save().then(
          user => {
            //if there's no error
            //authenticating again, to ensure that user registration was successful
            passport.authenticate("local")(req, res, () =>
              res.status(200).json({
                success: true,
                status: "registration successful, good job"
              })
            );
          },
          err => res.status(500).json({ err: err })
        );
        //on client side, client can simply check the value of success flag,..
        //..to see if registration was successful or not
      }
    }
  );
});

//login route
router.post("/login", passport.authenticate("local"), (req, res, next) => {
  //^^first the auth fn. is executed, and if successful, only then the callback is executed.
  //if there's any error in passport auth, err is sent back to client. thus it's handled.

  //issuing token to user when s/he logs in
  const token = authenticate.getToken({ _id: req.user._id });

  res.status(200).json({
    success: true,
    status: "you're logged in now, v nice",
    token: token //passing back the token to the client
  });
});

//logout route
router.get("/logout", (req, res, next) => {
  if (req.session) {
    //if a session associated with that user exists
    req.session.destroy(); //destroying the session associated with that user on the server side
    res.clearCookie("session-id"); //clearing the cookie for the session on the client side..
    //..so that it's not sent in further headers, and..
    //..it won't refer to the sessiion that doesn't exist anymore
    res.redirect("/"); //redirecting to the homepage
  } else {
    //if a session associated with that user doesn't exist
    //that means the user isn't logged in at all
    const err = new Error("bro you're not even logged in");
    err.status = 403;
    next(err);
  }
});

module.exports = router;
