const path = require('path');

const express = require('express');
const { check } = require('express-validator/check');

const adminController = require('../controllers/admin');

const isAuth = require('../middleware/is-auth');

const router = express.Router();

// /admin/add-product => GET
router.get('/add-product', isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get('/products', isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post('/add-product', [
    check('title').
        isString().
        withMessage('No special charaters in item title').
        isLength({ min: 3 })
        .withMessage('title too short')
        .trim(),
    check('imageUrl').isURL(),
    check('price').isFloat(),
    check('description')
        .isLength({ min: 5, max: 400 })
        .trim()

], isAuth, adminController.postAddProduct);

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct);

router.post('/edit-product', [
    check('title').
        isAlphanumeric().
        withMessage('No special charaters in item title').
        isLength({ min: 3 })
        .withMessage('title too short')
        .trim(),
    check('imageUrl').isURL(),
    check('price').isFloat(),
    check('description')
        .isLength({ min: 5, max: 400 })
        .trim()

], isAuth, adminController.postEditProduct);

router.post('/delete-product', isAuth, adminController.postDeleteProduct);

module.exports = router;
