const User = require('../../models/User');
const jwt = require('jsonwebtoken');

exports.auth = async (req, res, next) => {

    // declaring my function
    function redirectNext(user, authToken) {
        // assifn token and user data in request
        req.token = authToken;
        req.user = user;
        return next();
    }

    try {

        // if have auth_token cookie in browser
        if (req.cookies.auth_token) {

            // get auth_token cookie from browser
            const authToken = req.cookies.auth_token;

            // jwt varify with cookie
            const jwtVarifyToken = jwt.verify(authToken, process.env.SECRET_KEY);

            // find user
            const user = await User.findOne({ _id: jwtVarifyToken._id });

            // if user exist
            if (user) {

                // calling my function
                redirectNext(user, authToken);

            }


        } else {
            // sending flash msg
            req.flash('error', 'Access Denied!');

            // redirect login page
            return res.status(400).redirect('/login');
        }


    } catch (error) {

        // clear cookie from this browser
        if (req.cookies.auth_token) {
            res.clearCookie('auth_token');
        }

        // sending flash msg
        req.flash('error', 'Something Went Wrong!');
        req.flash('error', 'Please Log In to your account!');

        // redirect login page
        return res.status(400).redirect('/login');

    }
}