package storage

import (
	"database/sql"
	"fmt"
	"log"
)

// Storage: Структура для слоя хранения данных.
// Хранит соединение с базой данных.
type Storage struct {
	db *sql.DB // Соединение с базой данных SQLite
}

// NewStorage создает новый экземпляр Storage.
// Принимает существующее соединение с базой данных.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{db: db}
}

// CreateUser: Создает нового пользователя в базе данных.
// Принимает логин и хеш пароля.
// Возвращает ID созданного пользователя и ошибку, если что-то пошло не так.
// Возвращает ошибку, если пользователь с таким логином уже существует.
func (s *Storage) CreateUser(login, passwordHash string) (int, error) {
	// SQL-запрос для вставки нового пользователя.
	// Игнорируем ID, так как он AUTOINCREMENT.
	query := `INSERT INTO users (login, password_hash) VALUES (?, ?)`

	// Выполняем запрос. db.Exec используется для операций, которые не возвращают строки (INSERT, UPDATE, DELETE).
	result, err := s.db.Exec(query, login, passwordHash)
	if err != nil {
		log.Printf("Storage.CreateUser: Ошибка при вставке пользователя '%s': %v", login, err)
		return 0, fmt.Errorf("failed to create user '%s': %w", login, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("Storage.CreateUser: Ошибка при получении LastInsertId после вставки пользователя '%s': %v", login, err)
		return 0, fmt.Errorf("failed to get last insert ID for user '%s': %w", login, err)
	}

	// LastInsertId возвращает int64. Преобразуем его в int.
	return int(id), nil
}
