const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require("passport");
const jsonwt = require("jsonwebtoken");
const key = require("../../setup/dbconfig");
const cookieParser = require("cookie-parser");

const Data = require("../../models/Data");

//@type   POST
//@route   /api/upload
//@desc   Upload new data to table
//@access   PRIVATE

router.post('/', verifyToken, (req, res) => {
    jsonwt.verify(req.token, key.secret, (err, authData) => {
        if (err) {
            res.render('login')
        } else {
            var email = authData.email;
            Person.findOne({ email })
                .then(person => {
                    const newData = new Data({
                        name: req.body.name,
                        email: authData.email
                    })
                    newData
                        .save()
                        .then(success => {
                            const email = person.email;
                            Data.find({ email }).then(data => {
                                return res.render('home', { person: person, message: "Data Uploaded Successfully", data: data });
                            }).catch(err => console.log(err));
                        })
                        .catch(err => console.log(err));
                }).catch(err => console.log(err))
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
        res.sendStatus(403);
    }
}

module.exports = router;