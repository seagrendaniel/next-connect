const mongoose = require('mongoose');
const User = mongoose.model('User');
const passport = require('passport');

exports.validateSignup = (req, res, next) => {
  req.sanitizeBody('name');
  req.sanitizeBody('email');
  req.sanitizeBody('password');

  // Name is non-null and 4-10 characters long
  req.checkBody('name', 'Enter a name').notEmpty();
  req.checkBody('name', 'Name must between 4 - 10 characters').isLength({min: 4, max: 10});
  
  // Email is non-null, valid and normalized
  req.checkBody('email', 'Enter a valid email').isEmail().normalizeEmail();
  
  // Password is non-null and 4-10 characters long
  req.checkBody('password', 'Enter a password').notEmpty();
  req.checkBody('password', 'Password must between 4 - 10 characters').isLength({min: 4, max: 10});

  const errors = req.validationErrors(); // puts all errors into an array
  if(errors){
    const firstError = errors.map(error => error.msg)[0];
    return res.status(400).send(firstError);
  }
  next();
};

exports.signup = async (req, res) => {
  const {name, email, password} = req.body;
  const user = await new User({name, email, password});
  await User.register(user, password, (err, user) => {
    if(err) {
      return res.status(500).send(err.message);
    }
    res.json(user.name);
  })
};

exports.signin = (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if(err) {
      return res.status(500).json(err.message);
    }
    if(!user) {
      return res.status(400).json(info.message);
    }

    req.logIn(user, err => {
      if(err) {
        return res.status(500).json(err.message)
      }

      res.json(user);
    })
  })(req, res, next)
};

exports.signout = (req, res) => {
  res.clearCookie("next-cookies.sid") // cookie that was created in our session config object that was passed to express session
  req.logout();
  res.json({message: "You are now signed out!"});
};

exports.checkAuth = (req, res, next) => { // runs as middleware to protect certain routes
  if(req.isAuthenticated()) {
    return next();
  }
  res.redirect('/signin');
};
