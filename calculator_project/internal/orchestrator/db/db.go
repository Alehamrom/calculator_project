package db

import (
	"database/sql"
	"fmt"
	"log"
	_ "modernc.org/sqlite"
	"strings"
)

const dbFileName = "calculator.db"

func InitDB(dbFileName string) (*sql.DB, error) {
	// Открываем файл базы данных.
	db, err := sql.Open("sqlite", dbFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Проверяем, что соединение активно.
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection not alive: %w", err)
	}

	// SQL-запросы для создания таблиц.
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		login TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS expressions (
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    expression_string TEXT,
    status TEXT, -- Pending, InProgress, Completed, Failed
	root_task_id TEXT NULL,
    result REAL NULL, -- Final numerical result if status is Completed (используем NULL)
    error_message TEXT NULL, -- <--- ДОБАВЬ ЭТУ КОЛОНКУ
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        expression_id TEXT,
        operation TEXT,
        arg1 TEXT,
        arg2 TEXT,
        status TEXT, -- Статус задачи (Pending, InProgress, Completed, Failed)
        result REAL NULL, -- Результат вычисления задачи (число). NULL, если не завершена или провалена.
        error_message TEXT NULL, -- Сообщение об ошибке, если статус Failed. NULL, если успешно.
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Время создания задачи
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Время последнего обновления статуса/результата
        -- completed_at DATETIME NULL, -- Эта колонка не нужна, updated_at достаточно для отслеживания последнего изменения.
        FOREIGN KEY (expression_id) REFERENCES expressions(id)
    );
	`

	// Выполняем SQL-запросы.
	_, err = db.Exec(createTablesSQL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	log.Printf("Database '%s' initialized successfully.", dbFileName)
	return db, nil
}

// isUniqueConstraintError: Вспомогательная функция для проверки уникального ограничения.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	// Проверка строки.
	return strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed")
}
