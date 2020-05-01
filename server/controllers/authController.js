const mongoose = require('mongoose');
const user = mongoose.model('User');

exports.validateSignup = (req, res, next) => {
  req.sanitizeBody('name');
  req.sanitizeBody('email');
  req.sanitizeBody('password');

  // Name is non-null and 4-10 characters long
  res.checkBody('name', 'Enter a name').notEmpty();
  req.checkBody('name', 'Name must between 4 - 10 characters').isLength({min: 4, max: 10});
  
  // Email is non-null, valid and normalized
  req.checkBody('email', 'Enter a valid email').isEmail().normalizedEmail();
  
  // Password is non-null and 4-10 characters long
  res.checkBody('password', 'Enter a password').notEmpty();
  req.checkBody('password', 'Password must between 4 - 10 characters').isLength({min: 4, max: 10});

  const errors = req.validationErrors();
  if(errors){
    const firstError = errors.map(error => error.msg)[0];
    return res.status(400).send(firstError);
  }
  next();
};

exports.signup = (req, res) => {
  const {name, email, password} = req.body;
  const user = await new User({name, email, password});
  await User.register(user, password, (err, user) => {
    if(err) {
      return res.status(500).send(err.message);
    }
    res.json(user);
  })
};

exports.signin = () => {};

exports.signout = () => {};

exports.checkAuth = () => {};
