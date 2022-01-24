const express = require('express');

const { check } = require('express-validator/check');

const authController = require('../controllers/auth');

const router = express.Router();

const User = require('../models/user');

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login', check('email')
    .isEmail()
    .withMessage('Please enter a correct email')
    .normalizeEmail(),
    check('password')
    .isLength({min: 5})
    .withMessage('invalid password')
    .trim(),
    authController.postLogin);

router.post('/signup', check('email')
    .isEmail()
    .withMessage('Please enter a valid email')
    .custom((value, { req }) => {
        return User.findOne({ email: value })
            .then(userDoc => {
                console.log(userDoc);
                if (userDoc) {
                    return Promise.reject('E-Mail already exists, please choose another one.')
                }
            })
    })
    .normalizeEmail(),
    check('password')
        .isLength({ min: 5 })
        .withMessage('Please enter a password with a length of at least 5 characters')
        .trim(),
    check('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        };
        return true;
    })
    .trim(),
    authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('new-password', authController.postNewPassword);

module.exports = router;