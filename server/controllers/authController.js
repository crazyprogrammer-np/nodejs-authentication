const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');


/**
 * get /login
 */
exports.loginPage = async (req, res) => {

    // data for page
    let data = {
        layout: './layouts/layout',
        title: 'User Login',
        oldInput: req.oldInput,
        successMessage: req.flash('success'),
        errorMessage: req.flash('error')
    }

    try {

        // if have auth named cookie in browser
        if (req.cookies.auth) {

            // get authToken from auth cookie
            const authToken = req.cookies.auth;

            // varify authToken using jwt
            const varifyToken = jwt.verify(authToken, process.env.SECRET_KEY);

            // find user from mongodb
            const user = await User.findOne({ _id: varifyToken._id });

            // if user exist in db
            if (user) {

                // redirect to homepage
                return res.status(200).redirect('/');

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
        req.flash('error', 'Something Went Wrong!');
        req.flash('error', 'Please Log In to your account!');

        // redirect login page
        return res.redirect('/login');

    }
}

/**
 * get /register
 */
exports.registerPage = async (req, res) => {

    let data = {
        layout: './layouts/layout',
        title: 'User Registrtion',
        oldInput: req.oldInput,
        successMessage: req.flash('success'),
        errorMessage: req.flash('error')
    }

    try {

        // if have auth named cookie in browser
        if (req.cookies.auth) {

            // get authToken from auth cookie
            const authToken = req.cookies.auth;

            // varify authToken using jwt
            const varifyToken = jwt.verify(authToken, process.env.SECRET_KEY);

            // find user from mongodb
            const user = await User.findOne({ _id: varifyToken._id });

            // if user exist in db
            if (user) {

                // redirect to homepage
                return res.status(200).redirect('/');

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
        req.flash('error', 'Something Went Wrong!');
        req.flash('error', 'Please Log In to your account!');

        // redirect login page
        return res.redirect('/register');

    }
}

/**
 * post /login
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
            return res.status(404).redirect('/login');
        }

        // compare client's password with encrypted password in database using BCRYPT
        const varifyPassword = await bcrypt.compare(password, user.password);

        // if passwird does not varify
        if (!varifyPassword) {
            req.flash('error', 'Invalid Password!');
            return res.status(401).redirect('/login');
        }

        // create authToken for user and this token has expiry of 60 days
        const authToken = jwt.sign(
            { _id: user._id },
            process.env.SECRET_KEY,
            { expiresIn: "60d" }
        );

        // store authToken in database
        user.tokens = user.tokens.concat({ token: authToken });

        // if token saved in db
        if (await user.save()) {

            // create "auth" cookie in browser which have expiry of 60 days
            res.cookie('auth', authToken, { maxAge: 5184000000, httpOnly: true });

            // flash message
            req.flash('success', 'Access Granted!');
            // redirect to authenticated
            return res.status(200).redirect('/');

        }

    } catch (error) {

        // flash message
        req.flash('error', 'An Error Occured While Logging User!');
        // redirect to login page
        return res.status(500).redirect('/login');

    }

}


/**
 * post /register
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

        return res.status(400).redirect('/register');

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
            return res.status(201).redirect('/login');

        }

    } catch (error) {

        req.flash('error', 'An Error Occured While Registering An User!');
        return res.status(500).redirect('/register');

    }

}


/**
 * get /logout
 */
exports.logout = async (req, res) => {

    try {

        // get user from middleware
        const user = req.user;
        // get token from middleware
        const token = req.token;

        // deleting current token by filtering array of tokens in db
        user.tokens = user.tokens.filter((currentElement) => {
            return currentElement.token !== token;
        });


        if (await user.save()) {
            // delete cookie from browser
            res.clearCookie("auth");
            // flash message
            req.flash('success', 'User Logged Out Successfully!');
            // redirect to login
            return res.status(200).redirect('/login');
        }


    } catch (error) {
        req.flash('error', 'An Error Occured While Logging Out User!');
        return res.status(500).redirect('/');
    }
}