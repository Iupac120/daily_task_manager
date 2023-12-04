
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import dotenv from "dotenv";
import pool from "../database/db.js";

dotenv.config();

const getProfile = (profile) => {
    const { id, emails, displayName, provider } = profile;
    if (emails?.length) {
        const email = emails[0].value;
        return {
            id,
            user_name: displayName.split(' ')[0],
            email,
            provider
        };
    }
    console.log("profileDATA",profile)
    return null;
}

passport.use(
    new GoogleStrategy({
        clientID: process.env.GOOGLECLIENT_ID,
        clientSecret: process.env.GOOGLECLIENT_SECRET,
        callbackURL: "/api/register/auth/google/callback",
        scope: ["profile", "email"]
    },
    async (accessToken, refreshToken, profile, done) => {
        console.log("googleProfile", profile);
        try {
            const existingGoogleAccount = await pool.query("SELECT * FROM users WHERE google_id = $1", [profile.id]);

            if (existingGoogleAccount.rows.length === 0) {
                const existingEmailAccount = await pool.query("SELECT * FROM users WHERE user_email = $1", [getProfile(profile).email]);

                if (existingEmailAccount.rows.length === 0) {
                    const newAccount = await pool.query("INSERT INTO users (user_name, user_email, google_id) VALUES ($1, $2, $3) RETURNING *",
                        [getProfile(profile).user_name, getProfile(profile).email, getProfile(profile).id]);

                    done(null, newAccount.rows[0]);
                }
            } else {
                done(null, existingGoogleAccount.rows[0]);
            }
        } catch (err) {
            done(err, false);
        }
    })
);

passport.use(
    new FacebookStrategy(
        {
            clientID: process.env.FACEBOOKCLIENT_ID,
            clientSecret: process.env.FACEBOOKCLIENT_SECRET,
            callbackURL: "/api/register/auth/facebook/callback",
            profileFields: ['emails', 'displayName', 'name', 'picture']
        },
        async (accessToken, refreshToken, profile, done) => {
            console.log("facebookProfile", profile);
            try {
                const existingFacebookAccount = await pool.query("SELECT * FROM users WHERE facebook_id = $1", [profile.id]);

                if (existingFacebookAccount.rows.length === 0) {
                    const existingEmailAccount = await pool.query("SELECT * FROM users WHERE user_email = $1", [getProfile(profile).email]);

                    if (existingEmailAccount.rows.length === 0) {
                        const newAccount = await pool.query("INSERT INTO users (user_name, user_email, facebook_id) VALUES ($1, $2, $3) RETURNING *",
                            [getProfile(profile).user_name, getProfile(profile).email, getProfile(profile).id]);

                        done(null, newAccount.rows[0]);
                    }
                } else {
                    done(null, existingFacebookAccount.rows[0]);
                }
            } catch (err) {
                done(err, false);
            }
        }
    )
);

passport.serializeUser((user, done) => {
    console.log("serial user",user)
    done(null, user.user_id);
});

passport.deserializeUser(async (id, done) => {
    try {
        console.log("id",id)
        const result = await pool.query("SELECT * FROM users WHERE user_id = $1", [id]);
        const user = result.rows[0];
        console.log("deserialer user",user)
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

export default passport;
 