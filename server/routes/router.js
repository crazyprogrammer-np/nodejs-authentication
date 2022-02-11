// load express router
const route = require('express').Router();

// controllers
const authController = require('../controllers/authController');
const dashboardController = require('../controllers/dashboardController');

// middlewares
const user = require('../middleware/auth/user');
const validator = require('../middleware/validations/validationRules');

// routes
route.get('/', user.auth, dashboardController.home);
route.get('/', authController.registerUserPage);
route.post('/register', validator.newUser, authController.register);
route.get('/login', authController.loginPage);
route.post('/login', authController.login);

module.exports = route