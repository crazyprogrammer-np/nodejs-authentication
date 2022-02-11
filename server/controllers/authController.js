const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');


/**
 * login page
 */
exports.loginPage = (req, res) => {
    res.send('login page');
}

/**
 * user registeration page
 */
exports.registerUserPage = (req, res) => {
    res.send('register page');
}

/**
 * check user login
 */
exports.login = async (req, res) => {

    // getting username and password
    var username = req.body.username;
    var password = req.body.password;

    try {

        // matching username or email of client from mongo database
        const user = await User.findOne({
            $or: [
                { email: username },
                { username: username }
            ]
        });

        // if user does not exist in db
        if (!user) return res
            .status(403)
            .json({ error: [{ message: "Cannot find User!" }] });

        // compare client's password with encrypted password in database using BCRYPT
        const varifyPassword = await bcrypt.compare(password, user.password);

        // if passwird does not varify
        if (!varifyPassword) return res
            .status(403)
            .json({ error: [{ message: "Invalid Password!" }] })

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

            return res.header('auth_token', token).status(201)
                .json({
                    success: [{
                        message: "Access Granrted!",
                        auth_token: token
                    }]
                });

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

        let errorsMessage = [];

        for (let i = 0; i < errors.length; i++) {
            errorsMessage.push({ message: errors[i].msg })
        }

        return res.status(422).json({ error: errorsMessage });

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

            return res
                .status(201)
                .json({
                    success:
                        [{ message: "User Registered Successfully!" }]
                })

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