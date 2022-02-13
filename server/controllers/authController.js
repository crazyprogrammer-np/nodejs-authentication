const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');


/**
 * login page
 */
exports.loginPage = async (req, res) => {

    let data = {
        layout: './layouts/auth',
        title: 'User Login',
        successMessage: req.flash('success'),
        errorMessage: req.flash('error')
    }

    // declaring function
    function redirectIfAuthenticated() {
        return res.redirect('/');
    }

    try {

        // if have auth cookie in browser
        if (req.cookies.auth) {

            // get auth cookie from browser
            const token = req.cookies.auth;

            // jwt varify with cookie
            const jwtVarifyToken = jwt.verify(token, process.env.SECRET_KEY);

            // find user
            const user = await User.findOne({ _id: jwtVarifyToken._id });

            // if user exist
            if (user) {

                // calling my function
                redirectIfAuthenticated();

            }

        } else {

            // else render login page
            res.render('auth/login', data);

        }

    } catch (error) {

        // clear cookie from this browser
        if (req.cookies.auth) {
            res.clearCookie('auth');
        }

        // sending flash msg
        req.flash('error', 'An Error Occured!');

        // redirect login page
        return res.redirect('/login');

    }
}

/**
 * user registeration page
 */
exports.registerUserPage = async (req, res) => {

    let data = {
        layout: './layouts/auth',
        title: 'User Registrtion',
        oldInput: req.oldInput,
        successMessage: req.flash('success'),
        errorMessage: req.flash('error')
    }

    // declaring function
    function redirectIfAuthenticated() {
        return res.redirect('/');
    }

    try {

        // if have auth cookie in browser
        if (req.cookies.auth) {

            // get auth cookie from browser
            const token = req.cookies.auth;

            // jwt varify with cookie
            const jwtVarifyToken = jwt.verify(token, process.env.SECRET_KEY);

            // find user
            const user = await User.findOne({ _id: jwtVarifyToken._id });

            // if user exist
            if (user) {

                // calling my function
                redirectIfAuthenticated();

            }

        } else {

            // else render login page
            res.render('auth/register', data);

        }

    } catch (error) {

        // clear cookie from this browser
        if (req.cookies.auth) {
            res.clearCookie('auth');
        }

        // sending flash msg
        req.flash('error', 'An Error Occured!');

        // redirect login page
        return res.redirect('/register');

    }
}

/**
 * check user login
 */
exports.login = async (req, res) => {

    // getting username and password
    var username = req.body.username;
    var password = req.body.password;

    try {

        // find username or email of client from mongodb
        const user = await User.findOne({
            $or: [
                { email: username },
                { username: username }
            ]
        });

        // if user does not exist in db
        if (!user) {
            req.flash('error', 'Cannot find User!');
            return res.redirect('/login');
        }

        // compare client's password with encrypted password in database using BCRYPT
        const varifyPassword = await bcrypt.compare(password, user.password);

        // if passwird does not varify
        if (!varifyPassword) {
            req.flash('error', 'Invalid Password!');
            return res.redirect('/login');
        }

        // create token for user and this token has expiry of 60 days
        const token = jwt.sign(
            { _id: user._id },
            process.env.SECRET_KEY,
            { expiresIn: "60d" }
        );

        // store token in database
        user.tokens = user.tokens.concat({ token: token });
        const saveToken = await user.save();

        if (saveToken) {

            res.cookie('auth', token, {
                maxAge: 5184000000, httpOnly: true
            });

            req.flash('success', 'Access Granted!');
            return res.redirect('/');

        }

    } catch (error) {

        return res
            .status(500)
            .json({
                error: [{
                    message: "An error occured while logging on user api!"
                }]
            })

    }

}


/**
 * register new user
 */
exports.register = async (req, res) => {

    // get validation results using express-validator
    const validationResults = validationResult(req);

    // if validation result have error means not empty
    if (!validationResults.isEmpty()) {

        let errors = validationResults.array();

        for (let i = 0; i < errors.length; i++) {
            req.flash('error', errors[i].msg);
        }

        return res.redirect('/register');

    }

    // encrypt client's password using BCRYPT
    const salt = await bcrypt.genSalt();
    const hasedPassword = await bcrypt.hash(req.body.password, salt);

    // create new user
    let user = new User({
        fullName: req.body.fullName,
        username: req.body.username,
        email: req.body.email,
        emailVarifiedAt: null,
        password: hasedPassword,
        avatar: null
    })

    try {

        // save user
        const result = await user.save(user);

        if (result) {

            req.flash('success', 'User Registered Successfully!');
            req.flash('success', 'Please Sign Into Your Account!');
            res.redirect('/login');

        }

    } catch (error) {

        return res
            .status(500)
            .json({
                error: [{
                    message: "An error occured while registering an user api!"
                }]
            })

    }

}


/**
 * logout user
 */
exports.logout = async (req, res) => {

    try {

        // deleting current token by filtering array of tokens in db
        req.user.tokens = req.user.tokens.filter((currentElement) => {
            return currentElement.token !== req.token;
        });

        if (await req.user.save()) return res
            .status(200)
            .json({
                success: [{
                    message: "User logged out successfully!"
                }]
            });


    } catch (error) {
        return res
            .status(500)
            .json({
                error: [{
                    message: "An error occured while user logging out!"
                }]
            })
    }
}