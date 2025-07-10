const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/auth.controller');

// Middleware pour vérifier si l'utilisateur est authentifié
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Non autorisé' });
};

// Routes d'authentification locale
router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/logout', isAuthenticated, authController.logout);
router.get('/me', authController.me);

// Routes d'authentification Google
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['openid', 'profile', 'email']
  })
);

router.get('/google/callback', 
  passport.authenticate('google', { 
    failureRedirect: '/login',
    successRedirect: process.env.FRONT_WEB_URL || 'http://localhost:3000',
    failureMessage: true
  })
);

module.exports = router;