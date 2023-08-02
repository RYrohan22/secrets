require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// var md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();


app.use(express.static(__dirname + '/public/'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));


// This is for cookie session
// Here data is not stored in cookie only session id is stored and data is stored in server side
app.use(session({
    secret: 'My little secret',
    resave: false,
    saveUninitialized: true,
}));

// This is authentication
app.use(passport.initialize()); // Initializing the passport package
app.use(passport.session()); // Using passport package for dealing with session



// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/rohanDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log("Mongoose is connected");
})
.catch((error) => {
    console.log("Could not connect to MongoDB:", error);
});

const userSchema = new mongoose.Schema({
    email: String,
    // username : { type: String, required: true },
    password: String,
    googleId: String,
    secrets: [String]
});


// This package is for hashing and salting our passwords and to save our user to mongoDB database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function (user, done) {
    done(null, user.id);
});


passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});




passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


// const newUser = new User({ 
//     email: req.body.username
// });

app.get("/", function (req, res) {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile']
    }));

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect("/secrets");
    });


app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});


app.get("/secrets", function (req, res) {
    User.find({
        "secrets": {
            $ne: null
        }
    }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {
                    usersWithSecrets: foundUsers
                });
            }
        }

    });
});


app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login")
    }
});



app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log("Error finding user:", err);
        } else {
            if (foundUser) {
                foundUser.secrets.push(submittedSecret);
                foundUser.save(function (err) {
                    if (err) {
                        console.log("Error saving user:", err);
                    } else {
                        console.log("Secret submitted and saved successfully!");
                        res.redirect("/secrets");
                    }
                });
            }
        }
    });
});



app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log("Error during logout:", err);
        }
        res.redirect("/");
    });
});


app.post("/register", function (req, res) {
    console.log(req.body);
    User.register({
        username: req.body.username
    }, req.body.password, function (err, user) {
        if (err) {
            console.log("Error during registration:", err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});



app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(3000, function () {
    console.log("Server is running successfully on port 3000");
});































