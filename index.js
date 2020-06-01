const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

app.use('/users', require("./routes/userRouter"));
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

mongoose.connect(
    process.env.ALIAS, 
    {
        useUnifiedTopology: true, 
        useNewUrlParser: true,
        useCreateIndex: true
    }, (err) => {
        if (err) throw err;
        console.log("Connection to MongoDB established.");
    }
);