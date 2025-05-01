package orchestrator // Указываем пакет как orchestrator

import (
	"database/sql"                  // Стандартный пакет Go для работы с базами данных
	"fmt"                           // Для форматирования ошибок
	_ "github.com/mattn/go-sqlite3" // SQLite драйвер. Импорт анонимный (_), так как мы используем его косвенно через пакет database/sql
	"log"                           // Для вывода сообщений (например, об успешной инициализации)
)

const dbFileName = "calculator.db" // Имя файла базы данных SQLite

// InitDB открывает соединение с базой данных SQLite и создает необходимые таблицы, если они еще не существуют.
// Возвращает указатель на объект *sql.DB для работы с базой данных и ошибку, если что-то пошло не так.
func InitDB() (*sql.DB, error) {
	// Открываем файл базы данных. Если файла нет, он будет создан.
	// Первый аргумент "sqlite3" - это имя драйвера, который мы импортировали анонимно.
	// Второй аргумент - строка подключения, в данном случае просто имя файла базы данных.
	db, err := sql.Open("sqlite3", dbFileName)
	if err != nil {
		// Если при открытии файла возникла ошибка, возвращаем ее с дополнительным контекстом.
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Проверяем, что соединение с базой данных активно.
	if err = db.Ping(); err != nil {
		db.Close() // Если соединение не активно, закрываем его перед возвратом ошибки.
		return nil, fmt.Errorf("database connection not alive: %w", err)
	}

	// SQL-запросы для создания таблиц, если они еще не существуют (CREATE TABLE IF NOT EXISTS).
	// Это безопасно запускать при каждом старте приложения.
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT, -- Уникальный ID пользователя, автоинкрементируется
		login TEXT UNIQUE NOT NULL,          -- Логин, должен быть уникальным и не пустым
		password_hash TEXT NOT NULL          -- Хеш пароля, не может быть пустым
	);

	CREATE TABLE IF NOT EXISTS expressions (
		id TEXT PRIMARY KEY,                 -- Уникальный ID выражения (тот, что видит пользователь)
		user_id INTEGER,                     -- ID пользователя (внешний ключ на таблицу users)
		expression_string TEXT,              -- Строка самого выражения
		status TEXT,                         -- Статус вычисления (например, 'pending', 'completed')
		result REAL,                         -- Результат вычисления (число с плавающей точкой), может быть NULL
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Время создания записи, по умолчанию текущее время
		FOREIGN KEY (user_id) REFERENCES users(id) -- Объявление внешнего ключа
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,                 -- Уникальный ID задачи
		expression_id TEXT,                  -- ID выражения, к которому относится задача (внешний ключ на expressions)
		operation TEXT,                      -- Операция задачи ("+", "-", "*", "/")
		arg1 TEXT,                           -- Первый аргумент (строка)
		arg2 TEXT,                           -- Второй аргумент (строка)
		status TEXT,                         -- Статус задачи ('pending', 'in_progress', 'completed', 'error')
		result REAL NULL,                    -- Результат задачи (число), может быть NULL
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Время создания задачи
		completed_at DATETIME NULL,          -- Время завершения задачи, может быть NULL
		FOREIGN KEY (expression_id) REFERENCES expressions(id) -- Объявление внешнего ключа
	);
	`

	// Выполняем SQL-запросы для создания таблиц.
	// Exec используется для выполнения команд, которые не возвращают строки (как CREATE TABLE).
	_, err = db.Exec(createTablesSQL)
	if err != nil {
		db.Close() // Если при создании таблиц возникла ошибка, закрываем соединение.
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Выводим сообщение об успешной инициализации.
	log.Printf("Database '%s' initialized successfully.", dbFileName)
	// Возвращаем открытое и готовое к работе соединение с базой данных.
	return db, nil
}

// Этот файл с кодом следует сохранить как internal/orchestrator/db.gopackage orchestrator // Указываем пакет как orchestrator
