const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();

// Middlewares para leer datos de formularios, JSON y archivos estáticos de /public
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de sesión
app.use(session({
    secret: 'yupifests_secreto_super_seguro',
    resave: false,
    saveUninitialized: false
}));

// Conexión a la base de datos en XAMPP
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'sistema_login'
});

db.connect((err) => {
    if (err) {
        console.error('Error conectando a MySQL:', err);
        return;
    }
    console.log('✅ Conectado a la base de datos sistema_login en XAMPP');
});

// --- VERIFICAR SESIÓN ACTIVA ---
app.get('/session', (req, res) => {
    if (req.session.loggedin) {
        res.json({ loggedin: true, nombre: req.session.nombre });
    } else {
        res.json({ loggedin: false });
    }
});

// --- RUTA DE REGISTRO ---
app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ success: false, message: 'Completa todos los campos.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)';

        db.query(query, [nombre, email, hashedPassword], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(400).json({ success: false, message: 'Error al registrar (quizá el correo ya está registrado).' });
            }
            req.session.loggedin = true;
            req.session.nombre = nombre;
            res.json({ success: true, nombre: nombre });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error en el servidor.' });
    }
});

// --- RUTA DE INICIO DE SESIÓN ---
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM usuarios WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Error en la base de datos.' });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Usuario no encontrado.' });
        }

        const usuario = results[0];
        const passwordMatch = await bcrypt.compare(password, usuario.password);

        if (passwordMatch) {
            req.session.loggedin = true;
            req.session.nombre = usuario.nombre;
            res.json({ success: true, nombre: usuario.nombre });
        } else {
            res.status(401).json({ success: false, message: 'Contraseña incorrecta.' });
        }
    });
});

// --- RUTA PARA CERRAR SESIÓN ---
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// Iniciar servidor en puerto 3000
app.listen(3000, () => {
    console.log('🚀 Servidor YupiFest\'s corriendo en http://localhost:3000');
});