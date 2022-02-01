import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv';

const env = dotenv.config({ path: './dev.env' });


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const port = 3000;

// TODO: remove this line when using DB
const users = [];

const verifyToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];

    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    }
    else {
        res.sendStatus(403);
    }
}

app.get('/api', (req, res) => {
  res.send('Welcome to the API');
});

// return all users
// example protected route
app.get('/api/users', verifyToken, (req: any, res) => {
    jwt.verify(req.token, process.env.SECRET, (err, authData) => {
        if (err) {
            res.sendStatus(403);
        }
        else {
            res.send(users);
        }
    });
});

//create a new user
app.post('/api/users', async (req, res) => {
    try {

        let user = req.body;

        const existingUser = users.find(u => u.email === user.email || u.username === user.username);
        if (existingUser) {
            throw new Error('User already exists');
        }

        const password = await bcrypt.hash(user.password, 10);

        user = {...user, ...{ password}};
         
        //TODO: Add user to DB
        users.push(user);
        res.status(201).send(user);
    }
    catch (err) {
        console.log(err);
        res.status(500).json(err);
    }
});

//login
app.post('/api/users/login', async (req, res) => {
    try {
        const user = req.body;

        //TODO: Lookup DB for user identified by email or username
        const userFound = users.find(u => u.email === user.identifier || u.username === user.identifier); 

        if (!userFound) {
            return res.status(404).send('User not found');
        }

        if (await bcrypt.compare(user.password, userFound.password)) {
            jwt.sign({user: userFound} , process.env.SECRET, { expiresIn: '12h' }, (err, token) => {
                res.status(200).json({
                    token
                });
            });
        }
        else{
            return res.status(401).send('Password incorrect');
        }
    }
    catch (err) {
        res.status(500).send(err);
    }
});

//forgot password
app.post('/api/users/forgot', (req, res, next) => {
    const identifier = req.body.identifier;

    //TODO: Lookup DB for user identified by email or username
    const userFound = users.find(u => u.email === identifier || u.username === identifier);

    if (!userFound) {
        return res.status(404).send('User not found');
    }

    const secret = process.env.SECRET + userFound.password;
    const payload = {
        email: userFound.email,
    };
    const token = jwt.sign(payload, secret, { expiresIn: '30m' });

    const link = `http://localhost:3000/api/users/reset/${userFound.username}/${token}`; 

    //TODO: send email with link

    res.status(200).send("link has been sent");
});

//reset password (redirects to reset page if token and username are valid)
app.get('/api/users/reset/:username/:token', async (req, res, next) => {
    const username = req.params.username;
    const token = req.params.token;

    //TODO: check if user exists in DB
    const userFound = users.find(u => u.username === username);

    if (!userFound) {
        return res.status(404).send('User not found');
    }

    const secret = process.env.SECRET + userFound.password;
    jwt.verify(token, secret, async (err, authData) => {
        if (err) {
            return res.status(401).send('Invalid token');
        }
        else {
            res.render('reset-password', {email: authData.email});
        }
    });
});

// reset password (updates password in DB)
app.post('/api/users/reset/:username/:token', async (req, res, next) => {
    const username = req.params.username;
    const token = req.params.token;

        //TODO: check if user exists in DB
        const userFound = users.find(u => u.username === username);

        if (!userFound) {
            return res.status(404).send('User not found');
        }
    
        const secret = process.env.SECRET + userFound.password;
        jwt.verify(token, secret, async (err, authData) => {
            if (err) {
                return res.status(401).send('Invalid token');
            }
            else {
                const password = await bcrypt.hash(req.body.password, 10);
                
                const user = {...userFound, ...{ password}};

                //TODO: update user in DB
                const index = users.findIndex(u => u.email === authData.email);
                users.splice(index, 1, user);

                res.status(200).send('Password updated');
            }
        });
});

app.listen(port, () => {
    console.log(`Listening at http://localhost:${port}`);
});
