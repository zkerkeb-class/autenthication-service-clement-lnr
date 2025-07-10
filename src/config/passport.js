const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const { Strategy: GoogleStrategy } = require('passport-openidconnect');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Configuration Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email'}, async (email, password, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return done(null, false, { message: 'Email non trouvé' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return done(null, false, { message: 'Mot de passe incorrect' });
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Configuration Google Strategy
passport.use(
  'google',
  new GoogleStrategy({
    issuer: 'https://accounts.google.com',
    authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenURL: 'https://oauth2.googleapis.com/token',
    userInfoURL: 'https://openidconnect.googleapis.com/v1/userinfo',
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:${process.env.PORT}/api/auth/google/callback`,
    scope: ['openid', 'profile', 'email'],
    state: true,
    nonce: undefined,
    skipUserProfile: false
  },

  async function verify(issuer, profile, cb) {
    try {
      console.log('profile', profile);
      
      if (!profile || !profile._json || !profile._json.email) {
        return cb(new Error('Profil Google incomplet'));
      }

      const email = profile._json.email;
      const firstName = profile._json.given_name || '';
      const lastName = profile._json.family_name || '';

      let user = await prisma.user.findUnique({
        where: { email: email }
      });

      if (!user) {
        user = await prisma.user.create({
          data: {
            email: email,
            firstName: firstName,
            lastName: lastName,
            password: ''
          }
        });
      }

      return cb(null, user);
    } catch (error) {
      console.error('Erreur dans verify:', error); // Pour le débogage
      return cb(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;