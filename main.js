const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = 'your_secret_key'; // Замените на ваш секретный ключ

// Параметры подключения к базе данных PostgreSQL
const pool = new Pool({
    user: 'your_username',
    host: 'localhost',
    database: 'your_database',
    password: 'your_password',
    port: 5432,
});

app.use(express.json());

// Метод регистрации
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10);

        // Вставляем пользователя в базу данных
        const result = await pool.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', [username, hashedPassword]);
        
        // Создаем JWT токен для зарегистрированного пользователя
        const token = jwt.sign({ id: result.rows[0].id, username: username }, secretKey, { expiresIn: '1h' });
        
        res.status(201).json({ token });
    } catch (error) {
        console.error('Ошибка при регистрации:', error);
        res.status(500).json({ message: 'Ошибка при регистрации' });
    }
});

// Метод аутентификации
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Получаем пользователя из базы данных
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        // Проверяем пароль
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Неверные учетные данные' });
        }

        // Создаем JWT токен для аутентифицированного пользователя
        const token = jwt.sign({ id: user.id, username: username }, secretKey, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error('Ошибка при аутентификации:', error);
        res.status(500).json({ message: 'Ошибка при аутентификации' });
    }
});

// Защищенный маршрут
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Вы зашли в защищенный маршрут' });
});

// Проверка токена
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Отсутствует токен' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Неверный токен' });
        }

        req.user = decoded;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
