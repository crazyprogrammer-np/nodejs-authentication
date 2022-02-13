// load .env file
require('dotenv').config({ path: '.env' });

const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const bodyParser = require("body-parser");
const expressSession = require('express-session');
const cookieParser = require('cookie-parser');
const oldInput = require('old-input');
const connectFlash = require('connect-flash');
const path = require('path');

const connectDB = require('./server/database/connection');
const app = express();


// set view engine
app.set('view engine', 'ejs');

// use express json
app.use(express.json());

// body-parser to parse request from html body
app.use(bodyParser.urlencoded({ extended: true }));

// use cookie-parser
app.use(cookieParser());

// use express-session
app.use(expressSession({
    secret: 'process.env.SECRET_KEY',
    saveUninitialized: false,
    resave: true
}));

// use old-input
app.use(oldInput);

// use express-ejs-layout
app.use(expressLayouts);

// use connect-flash
app.use(connectFlash());

// load routers
app.use('/', require('./server/routes/router'));

// use static folder
app.use('/public', express.static(path.resolve(__dirname, "public")));

// getting port value from config.env file else port value is 8080
const PORT = process.env.PORT || 8080;

// start listnening the appp
app.listen(PORT, () => {

    // show msg in console that server is runninr
    console.log(`Server is running on http://localhost:${PORT}`);

    // connect Database mongodb
    connectDB();

});