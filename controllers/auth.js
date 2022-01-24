const User = require('../models/user');
const bcrypt = require('bcryptjs');
const { redirect } = require('express/lib/response');
const nodeMailer = require('nodemailer');
const sendGridTransport = require('nodemailer-sendgrid-transport');
const crypto = require('crypto');
const { validationResult } = require('express-validator/check');

const transporter = nodeMailer.createTransport(sendGridTransport({
  auth: {
    api_key: process.env.MAILER_API_KEY
  }
}));

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: req.flash('error'),
    oldInput: {
      email: '',
      password: '',
    },
    validationErrors: [],
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: req.flash('error'),
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationErrors: [],
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  let errors = validationResult(req);
  console.log(errors);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
      },
      validationErrors: errors.array(),
    });
  }
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        // console.log(user)
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'invalid email or password',
          oldInput: {
            email: email,
            password: password,
          },
          validationErrors: []
        });
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
            return res.status(422).render('auth/login', {
              path: '/login',
              pageTitle: 'Login',
              errorMessage: 'invalid email or password',
              oldInput: {
                email: email,
                password: password,
              },
              validationErrors: []
            });
          }
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        })
        .catch(err => {
          const error = new Error(err);
          error.httpStatusCode = 500;
          return next(error);
        });
  });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  console.log(errors);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    });
  }
  bcrypt.hash(password, 12).then(hashedPassword => {
    const user = new User({
      email: email,
      password: hashedPassword,
      cart: { items: [] }
    });
    return user.save();
  })
    .then(result => {
      res.redirect('/login')
      return transporter.sendMail({
        to: email,
        from: 'roo18002@byui.edu',
        subject: 'Signup Success',
        html: '<h1> You seuccesfully signed up!</h1>'
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  };
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset',
    errorMessage: message,
  })
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset')
    }
    const token = buffer.toString('hex');
    User.findOne({email: req.body.email})
    .then(user => {
      if (!user) {
        req.flash('error', 'No account found with that email.');
        return res.redirect('/reset');
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 3600000;
      return user.save();
    })
    .then(result => {
      res.redirect('/');
      console.log(req.body.email);
      transporter.sendMail({
        to: req.body.email,
        from: 'roo18002@byui.edu',
        subject: 'Password Reset',
        html: `
          <p>You request a password reset<p>
          <p>Click <a href="http://localhost:3000/reset/${token}">"here</a> to reset your password<p>
        `
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
  })
}

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  console.log(token);
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then(user => {
      console.log(user);
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'Reset Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token,
      })
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });

  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  };
}

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken, 
    resetTokenExpiration: {$gt: Date.now()}, 
    _id: userId,
    })
    .then(user => {
      resetUser = user;
      return bcrypt.hash(newPassword,12);
    })
    .then(hashedPassword => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(result => {
      res.redirect('/login');
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });

};
