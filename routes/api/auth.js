const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require("passport");
const jsonwt = require("jsonwebtoken");
const key = require("../../setup/dbconfig");
const cookieParser = require("cookie-parser");
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const Data = require("../../models/Data");
const Person = require("../../models/Person");

//@type   POST
//@route   /api/auth/register
//@desc   User registration
//@access   PUBLIC

router.post('/register', (req, res) => {
    Person.findOne({ email: req.body.email })
        .then(person => {
            if (person) {
                return res.render('register', { error: "email is already exists" })
            } else {
                const newPerson = new Person({
                        name: req.body.name,
                        email: req.body.email,
                        password: req.body.password
                    })
                    //Encrypt password using bcrypt
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newPerson.password, salt, (err, hash) => {
                        if (err) throw err;
                        newPerson.password = hash;
                        newPerson
                            .save()
                            .then(person => {
                                return res.render('login')
                            })
                            .catch(err => console.log(err));
                    });
                });
            }
        })
        .catch(err => console.log(err))

});

//@type   POST
//@route   /api/auth/login
//@desc   User Authentication
//@access   PUBLIC

router.post("/login", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    Person.findOne({ email })
        .then(person => {
            if (!person) {
                return res.render('login', { email: email, error: "email not exists" })
            }
            bcrypt
                .compare(password, person.password)
                .then(isPerson => {
                    if (isPerson) {
                        //use payload and create token for user
                        const payload = {
                            id: person.id,
                            name: person.name,
                            email: person.email
                        };
                        jsonwt.sign(
                            payload,
                            key.secret, { expiresIn: 3600 },
                            (err, token) => {
                                res.cookie('auth', "Bearer " + token, { maxAge: 360000 });
                                const email = person.email;
                                Data.find({ email }).then(data => {
                                    return res.render('home', { person: person, message: "User logged in successfully", data: data });
                                }).catch(err => console.log(err));
                            }
                        );
                    } else {
                        return res.render('login', { email: email, error: "Username or Password is not correct" })
                    }
                })
                .catch(err => console.log(err));
        })
        .catch(err => console.log(err));
});


//@type   GET
//@route   /api/auth/logout
//@desc   User Logout Operation
//@access   PRIVATE

router.get("/logout", (req, res) => {
    res.clearCookie('auth');
    res.render('login');
});

//@type POST
//@route /api/auth/forgotpassword
//@desc Send OTP to user email to reset password
//@access PUBLIC

router.post("/forgotpassword", (req, res) => {
    const email = req.body.email;
    Person.findOne({ email })
        .then(person => {
            if (!person) {
                return res
                    .status(400)
                    .json({ error: "Email not exists" });
            }
            // return res.json({ email: person.email, OTP: "Random OTP which need to send to the email" });
            var uniquecode = Math.floor(1000 + Math.random() * 9000);
            Person.findOneAndUpdate({ email: person.email }, { $set: { code: uniquecode } })
                .then(success => {
                    const msg = {
                        to: success.email,
                        from: 'saivardhanpoloju@gmail.com',
                        subject: 'Password reset Code',
                        text: 'Your are requested to change your password. Here is the code to reset your password',
                        html: '<h1>' + uniquecode + '</h1>',
                    };
                    sgMail.send(msg).then(success => {
                        return res.render("resetpassword");
                    }).catch(err => console.log(err));
                }).catch(err => console.log(err));
        })
        .catch(err => console.log(err));
});

//@type POST
//@route /api/auth/resetpassword
//@desc Reset password
//@access PUBLIC

router.post("/resetpassword", (req, res) => {
    const email = req.body.email;
    const code = req.body.code;
    const password = req.body.password;
    Person.findOne({ email })
        .then(person => {
                if (!person) {
                    return res
                        .status(400)
                        .json({ error: "Email not exists" });
                } else if (person.code != code) {
                    return res.status(400).json({ error: "Please enter valid code" });
                } else {
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(password, salt, (err, hash) => {
                            if (err) throw err;
                            Person.findOneAndUpdate({ email: person.email }, { $set: { password: hash } })
                                .then(success => {
                                    return res.json({ status: "Password updated successfully" })
                                }).catch(err => console.log(err));
                        });
                    });
                }
            }

        )
        .catch(err => console.log(err));
});

//@type   get
//@route   /api/auth/updateshow
//@desc   User details update
//@access   PRIVATE


router.get('/updateshow', verifyToken, (req, res) => {
    jsonwt.verify(req.token, key.secret, (err, authData) => {
        if (err) {
            res.render('home')
        } else {
            Person.findOne({ email: authData.email })
                .then(person => {
                    if (person) {
                        return res.render('update', { person: person })
                    } else {
                        return res.render('login')
                    }
                })
                .catch(err => console.log(err))
        }
    })
});

//@type   POST
//@route   /api/auth/update
//@desc   User details update
//@access   PRIVATE


router.post('/update', verifyToken, (req, res) => {
    jsonwt.verify(req.token, key.secret, (err, authData) => {
        if (err) {
            res.render('login')
        } else {
            var name, password;
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(req.body.password, salt, (err, hash) => {
                    if (err) throw err;
                    password = hash;
                    Person.findOne({ email: authData.email })
                        .then(person => {
                            if (req.body.name) {
                                name = req.body.name;
                            } else {
                                name = person.name;
                            }
                            Person.findOneAndUpdate({ email: authData.email }, { $set: { name: name, password: password } })
                                .then(person => {
                                    const email = person.email;
                                    Data.find({ email }).then(data => {
                                        return res.render('home', { person: person, message: "Profile Updated successfully", data: data })
                                    }).catch(err => console.log(err));
                                })
                                .catch(err => console.log(err));
                        })
                        .catch(err => console.log(err))
                });
            });
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