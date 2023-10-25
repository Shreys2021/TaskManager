const express = require('express');
const app = express();
const mongoose = require('mongoose');
const path = require('path');
const ejsMate = require('ejs-mate');
const methodOverride = require('method-override');
const Task = require('./models/Task');
const User = require('./models/User')
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const session = require('express-session');


// const crypto = require('crypto');

// // Generate a random secret key
// const secretKey = crypto.randomBytes(32).toString('hex');
// console.log('Secret Key:', secretKey);

mongoose.connect('mongodb+srv://shreyas:shreyas@cluster0.gsz3sqe.mongodb.net/?retryWrites=true&w=majority', {
    useNewUrlParser: true,

    useUnifiedTopology: true

}).then(() => {
    console.log("Connection open");
}).catch(err => {
    console.log("OH NO ERROR");
    console.log(err);
})

passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: "aa191a2316b2bd14ab84723bad4463a223720d7edc4d077cdaf52e3a2136b47e", // Replace with your secret key
}, (jwt_payload, done) => {
    // You can check the payload to find the user, e.g., find the user by ID
    // Example: User.findById(jwt_payload.sub, (err, user) => {
    //   if (err) return done(err, false);
    //   if (user) return done(null, user);
    //   else return done(null, false);
    // });
}));


passport.use(new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password',
    },
    async (username, password, done) => {
        try {
            const user = await User.findOne({ username });

            if (!user) {
                return done(null, false, { message: 'Incorrect username' });
            }
            console.log(password)
            console.log(user.password)

            const isPasswordValid = await bcrypt.compare(password, user.password);
            console.log(isPasswordValid)

            if (!isPasswordValid) {
                return done(null, false, { message: 'Incorrect password' });
            }

            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
));

app.use(express.urlencoded({ extended: true }))
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(methodOverride('_method'));
app.use(flash());

app.use(session({
    secret: "aa191a2316b2bd14ab84723bad4463a223720d7edc4d077cdaf52e3a2136b47e",
    resave: false,
    saveUninitialized: true,
}));

app.get('/', async (req, res) => {
    res.render('task/index');
});

app.get('/tasks', async (req, res) => {
    try {
        const tasks = await Task.find({});
        res.render('task/show', { tasks });
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
})

app.post('/AddTask', async (req, res) => {
    try {
        const { title, description } = req.body;
        const newTask = new Task(req.body);
        await newTask.save();
        res.redirect('/tasks');
    } catch (error) {
        res.status(400).json({ error: 'Failed to create a task' });
    }
});

app.get('/task/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const task = await Task.findById(id);
        if (!task) {
            return res.status(404).send('Task not found');
        }
        res.render('task/view', { task });
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

app.delete('/task/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await Task.deleteOne({ _id: id });
        res.redirect('/tasks');
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

app.get('/login', (req, res) => {
    res.render('user/login');
});

app.post('/login', (req, res, next) => {
    console.log('Request Body:', req.body); // Debugging line
    next();
}, passport.authenticate('local', {
    failureFlash: true,
    failureRedirect: '/login' // Redirect back to the login page on failed login
}), (req, res) => {
    // Successful login - Redirect to the desired page (e.g., '/tasks')
    res.redirect('/tasks');
});
// GET request for the registration page
app.get('/register', (req, res) => {
    res.render('user/register'); // Render the registration form
});

// POST request to handle user registration
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if the username or email already exists in the database
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash the password using 'bcrypt'
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create a new user and store their credentials in the database
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        // Generate a JWT token for the user
        const token = jwt.sign({ userId: newUser._id }, 'your-secret-key', { expiresIn: '1h' });

        // Send the token to the client or use it as needed for authentication
        // res.json({ token });

        // Redirect to the '/task' page after successful registration
        res.redirect('/tasks');
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Registration failed' });
    }
});


app.all('*', (req, res, next) => {
    res.send("NO PAGE FOUND");
})

app.listen(3000, () => {
    console.log("listening on port 3000");
})
