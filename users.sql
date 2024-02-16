CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
-- Создание роли/пользователя
CREATE ROLE your_username WITH LOGIN PASSWORD 'your_password';

-- Предоставление прав доступа к таблице users
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO your_username;
