const User = require('../../models/User');
const jwt = require('jsonwebtoken');

exports.auth = async (req, res, next) => {

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

                // sending token and user information on next request
                req.token = authToken;
                req.user = user;
                return next();

            }


        } else {

            // sending flash msg
            req.flash('error', 'Access Denied!');

            // redirect login page
            return res.status(401).redirect('/login');
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
        return res.status(401).redirect('/login');

    }
}