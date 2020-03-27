const express = require("express");
const bodyparser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const auth = require("./routes/api/auth");
const upload = require("./routes/api/upload");
const jsonwt = require("jsonwebtoken");
const key = require("./setup/dbconfig");
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());
app.use(cookieParser());

const db = require("./setup/dbconfig").dbconnection;

mongoose.set('useNewUrlParser', true);
mongoose.set('useUnifiedTopology', true);
mongoose.set('useFindAndModify', false);

mongoose.
connect(db).
then(() => console.log("Mongodb connected successfully")).
catch(err => console.log(err));

//Passport middleware
app.use(passport.initialize());

//Config for JWT strategy
require("./strategies/jsonwtStrategy")(passport);

app.set("view engine", "ejs");
//static folder
app.use(express.static("./views"));

app.get('/', verifyToken, (req, res) => {

    jsonwt.verify(req.token, key.secret, (err, authData) => {
        if (err) {
            res.render("login");
        } else {
            res.json({ email: authData.email });
        }
    })
});

function verifyToken(req, res, next) {
    const bearerHeader = req.cookies;
    if (typeof bearerHeader.auth !== 'undefined') {
        const bearer = bearerHeader.auth.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    } else {
        res.render("login");
    }

}

app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/login", (req, res) => {
    res.render("login");
})

app.get("/forgotpassword", (req, res) => {
    res.render("forgotpassword");
})

app.get("/resetpassword", (req, res) => {
    res.render("resetpassword");
})

app.use("/api/auth", auth);
app.use("/api/upload", upload);

const port = process.env.PORT || 3000;

app.listen(port, () => console.log(`Server is running on port ${port}`));