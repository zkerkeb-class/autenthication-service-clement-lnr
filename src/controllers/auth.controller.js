const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();
const passport = require('passport');

exports.register = async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  
  console.log('📝 Tentative d\'inscription:', { email, firstName, lastName });
  
  // Validation des données
  if (!email || !password || !firstName || !lastName) {
    return res.status(400).json({
      success: false,
      message: 'Tous les champs sont requis (email, password, firstName, lastName)',
      data: null
    });
  }
  
  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Le mot de passe doit contenir au moins 6 caractères',
      data: null
    });
  }
  
  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findUnique({
      where: { email: email }
    });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Un utilisateur avec cet email existe déjà',
        data: null
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName
      }
    });
    
    console.log('✅ Utilisateur créé avec succès:', user.id);
    
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    console.error('❌ Erreur lors de la création utilisateur:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la création de l\'utilisateur',
      data: null,
      error: error.message
    });
  }
};

exports.login = (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return res.status(500).json({ 
        success: false, 
        message: 'Error during authentication',
        data: null
      });
    }
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: info.message || 'Email or password incorrect',
        data: null
      });
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json({ 
          success: false, 
          message: 'Error during login',
          data: null
        });
      }

      return res.status(200).json({ 
        success: true, 
        message: 'Login successful', 
        data: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    });
  })(req, res, next);
};

exports.logout = (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Error during logout',
        data: null
      });
    }
    res.status(200).json({ 
      success: true,
      message: 'Logout successful',
      data: null
    });
  });
};

// Route pour vérifier l'état de connexion
exports.me = (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      success: true,
      message: 'Authenticated user',
      data: {
        id: req.user.id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName
      }
    });
  } else {
    res.json({
      success: false,
      message: 'Not authenticated',
      data: null
    });
  }
};

exports.callback = (req, res, next) => {
  passport.authenticate('google', async (err, profile) => {
    try {
      if (err) {
        console.error('Erreur Google:', err);
        return res.redirect('/login?error=google_auth_failed');
      }

      if (!profile || !profile._json || !profile._json.email) {
        console.error('Profil Google incomplet:', profile);
        return res.redirect('/login?error=invalid_profile');
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
            password: '' // Mot de passe vide pour les utilisateurs Google
          }
        });
      }
      // Connexion de l'utilisateur
      req.logIn(user, (err) => {
        if (err) {
          console.error('Erreur de connexion:', err);
          return res.redirect('/login?error=login_failed');
        }
        return res.redirect(process.env.FRONT_WEB_URL || 'http://localhost:3000');
      });
    } catch (error) {
      console.error('Erreur dans le callback Google:', error);
      return res.redirect('/login?error=server_error');
    }
  })(req, res, next);
};