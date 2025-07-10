// app.js
const express = require('express');
const session = require('express-session');
const passport = require('./config/passport');
const cors = require('cors');
const authRoutes = require('./routes/auth.route');

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.FRONT_WEB_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400 // 24 heures
}));

app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});

// Configuration des sessions
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 heures
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true
  }
}));

// Initialisation de Passport
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/api/auth', authRoutes);

// Route de test
app.get('/', (req, res) => {
  res.send('Welcome to the Apex auth API !');
});

// Gestion des erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Erreur serveur' });
});

const PORT = process.env.PORT || 4003;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});