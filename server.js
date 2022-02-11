// load .env file
require('dotenv').config({ path: '.env' });

const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const oldInput = require('old-input');
const flash = require('connect-flash');
const path = require('path');

const connectDB = require('./server/database/connection');
const app = express();

// set view engine
app.set('view engine', 'ejs');

// use express json
app.use(express.json());

// use express-ejs-layout
app.use(expressLayouts);

// use static folder
app.use('/public', express.static(path.resolve(__dirname, "public")));

// use old-input
app.use(oldInput);

// use connect-flash
app.use(flash());

// load routers
app.use('/', require('./server/routes/router'));

// getting port value from config.env file else port value is 8080
const PORT = process.env.PORT || 8080;

// start listnening the appp
app.listen(PORT, () => {

    // show msg in console that server is runninr
    console.log(`Server is running on http://localhost:${PORT}`);

    // connect Database mongodb
    connectDB();

});