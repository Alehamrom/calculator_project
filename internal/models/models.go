package models

import (
	"database/sql" // Для типов sql.NullString, sql.NullFloat64
	"time"         // Для типа time.Time

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims: Структура для дополнительных данных в JWT токене (payload).
// Встраиваем jwt.RegisteredClaims для стандартных полей (iat, exp, sub и т.д.).
type CustomClaims struct {
	UserID int64 `json:"user_id"` // ID пользователя
	jwt.RegisteredClaims
}

// User: Структура, представляющая пользователя в системе.
// Соответствует полям в таблице 'users'.
type User struct {
	ID           int64     `json:"id"`         // Уникальный ID пользователя
	Login        string    `json:"login"`      // Логин пользователя (должен быть уникальным)
	PasswordHash string    `json:"-"`          // Хеш пароля пользователя (результат bcrypt)
	CreatedAt    time.Time `json:"created_at"` // Время регистрации пользователя
}

// ExpressionStatus - Статусы выражений, поставленных в очередь.
const (
	ExpressionStatusPending    string = "Pending"    // Выражение принято, задачи еще не начали выполняться
	ExpressionStatusInProgress string = "InProgress" // Некоторые или все задачи выполняются
	ExpressionStatusCompleted  string = "Completed"  // Все задачи выражения успешно выполнены
	ExpressionStatusFailed     string = "Failed"     // Одна или несколько задач выражения завершились с ошибкой
)

// Expression: Структура, представляющая арифметическое выражение, поставленное в очередь на вычисление.
// Соответствует полям в таблице 'expressions'.
type Expression struct {
	ID               string          `json:"id"`                     // ID выражения (UUID)
	UserID           int64           `json:"user_id"`                // ID пользователя, которому принадлежит выражение
	ExpressionString string          `json:"expression_string"`      // Строковое представление выражения (например, "2+2*2")
	Status           string          `json:"status"`                 // Статус выражения (например, "pending", "calculating", "completed", "failed")
	RootTaskID       sql.NullString  `json:"root_task_id,omitempty"` // ID корневой задачи вычисления (UUID). omitempty не включает поле в JSON, если оно нулевое/пустое.
	FinalResult      sql.NullFloat64 `json:"result,omitempty"`
	ErrorMessage     sql.NullString  `json:"error_message,omitempty"` // Сообщение об ошибке, если вычисление завершилось неудачно. sql.NullString для NULL.
	CreatedAt        time.Time       `json:"created_at"`              // Время создания выражения
	UpdatedAt        time.Time       `json:"updated_at"`              // Время последнего обновления статуса/результата. (Возможно sql.NullTime если в БД может быть NULL до первого обновления)
}

// Task statuses - Статусы отдельных вычислительных задач, на которые разбивается выражение.
const (
	TaskStatusPending    string = "Pending"    // Задача ожидает выполнения (все аргументы известны)
	TaskStatusInProgress string = "InProgress" // Задача взята Агентом в работу
	TaskStatusCompleted  string = "Completed"  // Задача успешно выполнена Агентом
	TaskStatusFailed     string = "Failed"     // Задача завершилась у Агента с ошибкой
)

// CalculationTask: Структура, представляющая одну вычислительную задачу.
// Соответствует полям в таблице 'tasks'.
type CalculationTask struct {
	ID           string          `json:"id"`                      // Уникальный ID задачи (генерируется как UUID)
	ExpressionID string          `json:"expression_id"`           // ID выражения, к которому относится задача
	Operation    string          `json:"operation"`               // Тип операции ("+", "-", "*", "/", "number")
	Arg1         string          `json:"arg1"`                    // Первый аргумент (число в виде строки ИЛИ ID задачи-зависимости)
	Arg2         string          `json:"arg2"`                    // Второй аргумент (число в виде строки ИЛИ ID задачи-зависимости)
	Status       string          `json:"status"`                  // Текущий статус задачи (используем константы TaskStatus*)
	Result       sql.NullFloat64 `json:"result,omitempty"`        // Результат вычисления задачи. Используем sql.NullFloat64, т.к. изначально NULL.
	ErrorMessage sql.NullString  `json:"error_message,omitempty"` // Сообщение об ошибке, если задача провалилась. Используем sql.NullString, т.к. изначально NULL.
	CreatedAt    time.Time       `json:"created_at"`              // Время создания задачи
	UpdatedAt    time.Time       `json:"updated_at"`              // Время последнего обновления статуса или результата задачи
}

type ExpressionDetailsResponse struct {
	Expression Expression        `json:"expression"` // Детали выражения
	Tasks      []CalculationTask `json:"tasks"`      // Список связанных задач
}
