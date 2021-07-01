import express from 'express';
import bodyParser from 'body-parser';
import { MongoClient, ObjectID } from 'mongodb';
import path from 'path';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { sendEmail } from './util/sendEmail';
import { v4 as uuid } from 'uuid';
import { getGoogleOauthUrl } from './util/getGoogleOauthUrl';
import { getGoogleUser } from './util/getGoogleUser';
import { updateOrCreateUserFromOauth } from './util/updateOrCreateUserFromOauth';
const app = express();

app.use(express.static(path.join(__dirname, '/build')));
app.use(bodyParser.json());

const withDB = async (operations, res) => {
    try {
        const client = await MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true })
        const db = client.db('my-blog');

        await operations(db);

        client.close();
    } catch (error) {
        res.status(500).json({ message: 'Error connecting to db', error });
    }
}

app.get('/api/articles/:name', async (req, res) => {
    withDB(async (db) => {
        const articleName = req.params.name;
        const articlesInfo = await db.collection('articles').findOne({ name: articleName });
        res.status(200).json(articlesInfo);
    }, res);
});

app.post('/api/articles/:name/upvote', async (req, res) => {
    withDB(async (db) => {
        const articleName = req.params.name;

        const articlesInfo = await db.collection('articles').findOne({ name: articleName });
        await db.collection('articles').updateOne({ name: articleName }, {
            '$set': {
                upvotes: articlesInfo.upvotes + 1,
            },
        });

        const updatedArticleInfo = await db.collection('articles').findOne({ name: articleName });
        res.status(200).json(updatedArticleInfo);
    }, res)

});

app.post('/api/articles/:name/add-comment', (req, res) => {
    const { username, text } = req.body;
    const articleName = req.params.name;
    withDB(async (db) => {
        const articleInfo = await db.collection('articles').findOne({ name: articleName });
        await db.collection('articles').updateOne({ name: articleName }, {
            '$set': {
                comments: articleInfo.comments.concat({ username, text })
            }
        });

        const updatedArticleInfo = await db.collection('articles').findOne({ name: articleName });
        res.status(200).json(updatedArticleInfo);


    }, res);
});

app.post('/api/login', async (req, res) => {

    const { email, password } = req.body;
    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');
    const user = await db.collection('users').findOne({ email });

    if (!user) return res.sendStatus(401);

    const { _id: id, isVerified, passwordHash, info } = user;

    const isCorrect = await bcrypt.compare(password, passwordHash);

    if (isCorrect) {
        jwt.sign({ id, isVerified, email, info }, process.env.JWT_SECRET, { expiresIn: '2d' }, (err, token) => {
            if (err) {
                res.status(500).json(err);
            }
            res.status(200).json({ token });
        });
    } else {
        res.sendStatus(401);
    }

})

app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;
    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');
    const user = await db.collection('users').findOne({ email });

    if (user) {
        res.sendStatus(409);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const verificationString = uuid();
    const startingInfo = {
        articles: []
    };

    const result = await db.collection('users').insertOne({
        email,
        passwordHash,
        info: startingInfo,
        isVerified: false,
        verificationString,
    })

    const { insertedId } = result;

    try {
        await sendEmail({
            to: email,
            from: 'snowroars@gmail.com',
            subject: 'Please verify email',
            text: `Thank you for signing up! To verify your email, click here: http://localhost:3000/verify-email/${verificationString}`
        });
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }

    jwt.sign({
        id: insertedId,
        email,
        info: startingInfo,
        isVerified: false
    },
        process.env.JWT_SECRET,
        {
            expiresIn: '2d',
        },
        (err, token) => {

            if (err) {
                return res.status(500).send(err);
            }
            res.status(200).json({ token })
        }
    );

})

// update user info route
app.put('/api/users/:userId', async (req, res) => {
    const { authorization } = req.headers;
    const { userId } = req.params;

    const updates = ({
        articles
    }) => ({
        articles
    })(req.body);

    if (!authorization) {
        return res.status(401).json({ message: 'No authorization header sent' });

    }

    const token = authorization.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Unable to verify code' })

        const { id, isVerified } = decoded;

        if (id !== userId) return res.status(403).json({ message: 'Not allowed to update that user\'s data. ' })
        if (!isVerified) return res.status(403).json({ message: 'You need to verify your email before you can update your data' })

        const client = await MongoClient.connect('mongodb://localhost:27017', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        const db = client.db('react-auth-db');
        const result = await db.collection('users').findOneAndUpdate(
            { _id: ObjectID(id) },
            { $set: { info: updates } },
            { returnOriginal: false },
        );
        const { email, info } = result.value;
        jwt.sign({ id, email, isVerified, info }, process.env.JWT_SECRET, { expires: '2d' }, (err, token) => {
            if (err) {
                return res.status(200).json(err)
            }
            res.status(200).json({ token });
        })

    })
})

// testEmailRoute.js
app.post('/api/test-email', async (req, res) => {
    try {
        await sendEmail({
            to: 'snowroars+test1@gmail.com',
            from: 'snowroars@gmail.com',
            subject: 'Does this work?',
            text: 'If youre reading this then it works',

        });
        res.sendStatus(200);
    } catch (e) {
        console.log(e);
        res.sendStatus(500);
    }
})

//Verify email route
app.put('/api/verify-email', async (req, res) => {
    const { verificationString } = req.body;
    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');
    const result = await db.collection('users').findOne({
        verificationString
    });

    if (!result) return res.status(401).json({ message: 'The email verification code is incorrect' });

    const { _id: id, email, info } = result;

    await db.collection('users').updateOne({ _id: ObjectID(id) }, {
        $set: { isVerified: true }
    });

    jwt.sign({ id, email, isVerified: true, info }, process.env.JWT_SECRET, { expiresIn: '2d' }, (err, token) => {
        if (err) return res.sendStatus(500);
        res.status(200).json({ token })
    })

});

app.put('/api/forgot-password/:email', async (req, res) => {
    const { email } = req.params;
    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');

    const passwordResetCode = uuid();

    const { result } = await db.collection('users')
        .updateOne({ email }, { $set: { passwordResetCode } });

    if (result.nModified > 0) {
        try {
            await sendEmail({
                to: email,
                from: 'snowroars@gmail.com',
                subject: 'Password Reset',
                text: `To reset your password, click this link:
                http://localhost:3000/reset-password/${passwordResetCode}`
            });
        } catch (e) {
            console.log(e);
            res.sendStatus(500);
        }
    }

    res.sendStatus(200);
})

app.put('/api/users/:passwordResetCode/reset-password', async (req, res) => {
    const { passwordResetCode } = req.params;
    const { newPassword } = req.body;
    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');

    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    const result = await db.collection('users')
        .findOneAndUpdate({ passwordResetCode }, {
            $set: { passwordHash: newPasswordHash },
            $unset: { passwordResetCode: '' }
        });
    if (result.lastErrorObject.n === 0) {
        return res.sendStatus(404);
    }

    res.sendStatus(200);
})

//get google oauth url route
app.get('/auth/google/url', (req, res) => {
    const url = getGoogleOauthUrl();
    res.status(200).json({ url });
});

//google oauth callback route -> for user to go back after they give permission to login with their account
app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;

    const oauthUserInfo = await getGoogleUser({ code });

    const updatedUser = await updateOrCreateUserFromOauth({ oauthUserInfo });
    const { _id: id, isVerified, email, info } = updatedUser;

    jwt.sign({ id, isVerified, email, info }
        , process.env.JWT_SECRET,
        (err, token) => {
            if (err) return res.sendStatus(500);
            res.redirect(`http://localhost:8000/login?token=${token}`)
        })
})

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname + '/build/index.html'));
})

app.listen(8000, () => console.log('Listening on port 8000...'));