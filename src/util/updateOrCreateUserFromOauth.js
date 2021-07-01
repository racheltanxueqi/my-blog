import { MongoClient } from 'mongodb';

export const updateOrCreateUserFromOauth = async ({ oauthUserInfo }) => {
    const {
        id: googleId,
        verified_email: isVerified,
        email,
    } = oauthUserInfo;

    const client = await MongoClient.connect('mongodb://localhost:27017', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = client.db('react-auth-db');
    const existingUser = await db.collection('users').findOne({ email });

    if (existingUser) {
        const result = await db.collection('users').findOneAndUpdate(
            { email },
            { $set: { googleId, isVerified } },
            { returnOriginal: false }
        );
        return result.value;
    } else {
        const result = await db.collection('users').insertOne({
            email,
            googleId,
            isVerified,
            info: {}
        });
        return result.ops[0];
    }
}