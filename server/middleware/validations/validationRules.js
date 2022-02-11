const { check } = require('express-validator');
const User = require('../../models/User');

/**
 * new user validations
 */

exports.newUser = [

    // name validation
    check('fullName')
        // required
        .trim().notEmpty().withMessage('Name is Required')
        // only character with whitespace
        .matches(/^[a-zA-Z ]*$/).withMessage('Invalid Name'),

    // name validation
    check('username')
        // required
        .trim().notEmpty().withMessage('Username is Required')
        // minimum character 4
        .isLength({ min: 4 }).withMessage('Username Must Have Minimum 4 Character')
        // no whitesapce allowed
        .not().matches(/^$|\s+/).withMessage("Username Can't Contain Whitespace")
        // check if username exist
        .custom(value => {
            return User.findOne({ username: value }).then(user => {
                if (user) {
                    return Promise.reject('Username already taken');
                }
            });
        }),

    // email address validation
    check('email')
        // required
        .trim().notEmpty().withMessage('E-mail Address is Required')
        // is email
        .normalizeEmail().isEmail().withMessage('Invalid E-mail Address')
        // check if email exist
        .custom(async value => {
            let user = await User.findOne({ 'email': value });
            if (user) {
                return Promise.reject('E-mail already in use');
            }
        }),

    // password validation
    check('password')
        // required
        .trim().notEmpty().withMessage('Password is Required')
        // minimum character 5
        .isLength({ min: 5 }).withMessage('Password Must Have Minimum 5 Character')
        // atleast 1 uppercase
        .matches(/(?=.*?[A-Z])/).withMessage('Password Must Have At Least One Uppercase')
        // atleast 1 lowercase
        .matches(/(?=.*?[a-z])/).withMessage('Password Must Have At Least One Lowercase')
        // atleast 1 number
        .matches(/(?=.*?[0-9])/).withMessage('Password Must Have At Least One Number')
        // atleast 1 special character
        .matches(/(?=.*?[#?!@$%^&*-])/).withMessage('Password Must Have At Least One Special Character')
        // no whitesapce allowed
        .not().matches(/^$|\s+/).withMessage('Password With White Space Not Allowed'),

    // confirm password validation
    check('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Password Confirmation does not match');
            }
            return true;
        })
]