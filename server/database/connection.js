const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        //mongodb connection
        const con = await mongoose.connect(process.env.MONGO_URI_LOCAL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        })
        console.log(`MongoDB Connected:${con.connection.host}`);
    }
    catch (error) {
        console.log(error);
        process.exit(1);
    }

}

module.exports = connectDB;