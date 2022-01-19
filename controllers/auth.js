const User = require('../models/user');
const bcrypt = require('bcryptjs');
const { redirect } = require('express/lib/response');

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: req.flash('error')
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: req.flash('error')
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  console.log(req.body);
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        // console.log(user)
        req.flash('error', 'invalid email or password');
        return res.redirect('/login');
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          console.log(doMatch);
          if (doMatch) {
            req.session.isAuthenticated = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          } else {
            req.flash('error', 'invalid email or password');
            res.redirect('/login')
          }
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        })
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  //nconst confirmPassword = req.bodt.confirmPassword;
  User.findOne({email: email}).then(userDoc => {
    //console.log(userDoc);
    if(userDoc) {
      req.flash('error', 'Email already in use!');
      return res.redirect('/signup')
    }
    return bcrypt.hash(password, 12).then(hashedPassword => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: {items: []}
      });
      return user.save();
    })
    .then(result => {
      res.redirect('/login')
    })
  })
  .catch(err => {
    console.log(err);
  });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};
