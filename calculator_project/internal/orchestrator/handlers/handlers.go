package handlers

import (
	localParser "calculator_project/internal/parser"
	// "context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	localAuth "calculator_project/internal/auth"
	localHTTP "calculator_project/internal/http"
	localModels "calculator_project/internal/models"

	"github.com/golang-jwt/jwt/v5"
	// "github.com/gorilla/mux"
)

// Структуры для запросов и ответов API

// Структура для тела запроса на вычисление выражения.
type CalculateRequest struct {
	Expression string `json:"expression"`
}

// Структура для тела ответа после создания выражения на вычисление.
type CalculateResponse struct {
	ID string `json:"id"` // ID созданного выражения
}

// RegisterRequest представляет структуру тела запроса для регистрации пользователя.
type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Структура для тела запроса на вход пользователя.
type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Структура для тела ответа при успешном входе пользователя (содержит токен).
type LoginResponse struct {
	Token string `json:"token"`
}

// Структура сервиса с зависимостями и ее конструктор

type APIService struct {
	DB *sql.DB

	// Конфигурация, необходимая обработчикам.
	JWTSecret string // Секретный ключ для подписи JWT токенов
	// Здесь можно будет добавить другие зависимости, например, менеджер задач и т.д.
}

// NewAPIService: Функция-конструктор для создания нового экземпляра APIService.
func NewAPIService(db *sql.DB, jwtSecret string) *APIService {
	return &APIService{
		DB:        db,
		JWTSecret: jwtSecret, // Сохраняем секрет в структуре
	}
}

// Реализация функций-обработчиков HTTP API

// RegisterHandler: Обработчик HTTP-запросов на регистрацию пользователя.
func (s *APIService) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получен запрос на регистрацию пользователя")
	defer r.Body.Close()

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Ошибка при декодировании тела запроса регистрации: %v", err)
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid request body format")
		return
	}

	if req.Login == "" || req.Password == "" {
		log.Println("Запрос на регистрацию с пустым логином или паролем.")
		localHTTP.RespondError(w, http.StatusBadRequest, "Login and password cannot be empty")
		return
	}

	hashedPassword, err := localAuth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Ошибка при хешировании пароля для пользователя '%s': %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	insertUserSQL := `INSERT INTO users (login, password_hash) VALUES (?, ?)`
	_, err = s.DB.Exec(insertUserSQL, req.Login, hashedPassword)

	if err != nil {
		if isUniqueConstraintError(err) {
			log.Printf("Ошибка регистрации: Логин '%s' уже существует.", req.Login)
			localHTTP.RespondError(w, http.StatusConflict, "Login already exists")
			return
		}
		log.Printf("Ошибка при вставке пользователя '%s' в базу данных: %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	log.Printf("Пользователь '%s' успешно зарегистрирован.", req.Login)
	localHTTP.RespondJSON(w, http.StatusOK, map[string]string{})
}

// LoginHandler: Обработчик HTTP-запросов на вход пользователя (POST /api/v1/login).
func (s *APIService) LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получен запрос на вход пользователя")

	defer r.Body.Close()

	// 1. Парсим тело запроса.
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Ошибка при декодировании тела запроса входа: %v", err)
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid request body format")
		return
	}

	// 2. Валидация входных данных.
	if req.Login == "" || req.Password == "" {
		log.Println("Запрос на вход с пустым логином или паролем.")
		localHTTP.RespondError(w, http.StatusBadRequest, "Login and password cannot be empty")
		return
	}

	// 3. Находим пользователя в базе данных по логину.
	// Выбираем ID, логин и хеш пароля пользователя.
	selectUserSQL := `SELECT id, login, password_hash FROM users WHERE login = ?`
	var userID int64
	var login string                // Читаем логин из БД
	var hashedPasswordFromDB string // Сюда считаем хеш из БД

	// QueryRow выполняет запрос, Scan считывает результат в переменные.
	err = s.DB.QueryRow(selectUserSQL, req.Login).Scan(&userID, &login, &hashedPasswordFromDB)

	if err != nil {
		// Обрабатываем ошибку, если пользователь не найден.
		if err == sql.ErrNoRows {
			log.Printf("Попытка входа: Пользователь '%s' не найден.", req.Login)
			// Возвращаем общую ошибку для неверных учетных данных (для безопасности).
			localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid login or password") // 401 Unauthorized
			return
		}
		// Обрабатываем другие ошибки базы данных.
		log.Printf("Ошибка при поиске пользователя '%s' в базе данных: %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// 4. Проверяем пароль.
	passwordMatch := localAuth.CheckPasswordHash(req.Password, hashedPasswordFromDB)

	if !passwordMatch {
		log.Printf("Попытка входа: Неверный пароль для пользователя '%s'.", req.Login)
		// Возвращаем ту же общую ошибку (не сообщаем, что логин найден, но пароль неверный).
		localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid login or password") // 401 Unauthorized
		return
	}

	// 5. Если логин и пароль верны, генерируем JWT токен.
	expirationTime := time.Now().Add(24 * time.Hour) // Время жизни токена

	// Создаем стандартные и кастомные claims (данные, которые будут храниться в токене).
	claims := &localModels.CustomClaims{
		UserID: userID, // Сохраняем ID пользователя в токене
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Время истечения токена
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // Время выдачи токена
			Subject:   fmt.Sprintf("%d", userID),          // "sub" - субъект, часто ID пользователя
		},
	}

	// Создаем новый JWT токен с нашими claims и выбранным методом подписи (HS256).
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен нашим секретным ключом из структуры APIService.
	tokenString, err := token.SignedString([]byte(s.JWTSecret)) // s.JWTSecret получаем из структуры

	if err != nil {
		// Если при подписи токена возникла ошибка (например, пустой секретный ключ), возвращаем 500.
		log.Printf("Ошибка при генерации JWT токена для пользователя '%s': %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// 6. Отправляем ответ с токеном.
	log.Printf("Пользователь '%s' успешно вошел в систему. Выдан токен.", req.Login)
	// Создаем структуру ответа и заполняем поле токеном.
	responsePayload := LoginResponse{Token: tokenString}
	// Отправляем успешный ответ 200 OK с JSON-телом, содержащим токен.
	localHTTP.RespondJSON(w, http.StatusOK, responsePayload)
}

// isUniqueConstraintError: Вспомогательная функция для проверки уникального ограничения.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed")
}

// CalculateHandler: Обработчик HTTP-запросов на вычисление выражения.
// Реализация логики парсинга нашим парсером и разбиения на задачи.
func (s *APIService) CalculateHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получен запрос на вычисление выражения")

	defer r.Body.Close()

	userID := int64(1) // Временно для тестирования CalculateHandler без middleware

	log.Printf("CalculateHandler: Запрос на вычисление выражения от пользователя с ID: %d", userID)

	// Оригинальный блок получения UserID из контекста (закомментирован)
	/*
		userID, ok := r.Context().Value(localAuth.UserIDKey).(int64)
		if !ok {
			log.Println("CalculateHandler: UserID не найден в контексте запроса. Запрос не авторизован или проблема middleware.")
			localHTTP.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not found in context") // Или 500
			return
		}
		log.Printf("CalculateHandler: Запрос на вычисление выражения от пользователя с ID: %d", userID)
	*/

	// 1. Парсим тело запроса.
	var req CalculateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Ошибка при декодировании тела запроса вычисления: %v", err)
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid request body format")
		return
	}

	// 2. Валидация входных данных (проверяем, что строка выражения не пустая).
	if req.Expression == "" {
		log.Println("Запрос на вычисление с пустым выражением.")
		localHTTP.RespondError(w, http.StatusBadRequest, "Expression cannot be empty")
		return
	}

	log.Printf("Попытка парсинга выражения: %s", req.Expression)

	// *** 3. Парсинг выражения нашим парсером и создание задач. ***
	// Создаем новый экземпляр парсера
	parserState := localParser.NewParser(req.Expression) // NewParser
	// Парсим выражение в дерево узлов
	rootNode, err := parserState.ParseExpression() // ParseExpression

	if err != nil {
		return
	}

	// Проверяем, что после парсинга не осталось необработанных символов
	parserState.SkipSpaces()
	if parserState.Pos < len(parserState.Input) {
		log.Printf("Ошибка парсинга: необработанные символы '%s' в конце выражения", parserState.Input[parserState.Pos:])
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid expression format: unexpected characters at the end")
		return
	}

	// Список для хранения сгенерированных задач
	tasksToSave := []localParser.CalculationTask{}

	// Обходим дерево узлов и формируем список задач
	// Результат обхода корневого узла - это ID последней задачи (или число), представляющей результат всего выражения.
	finalResultIDOrValue, err := localParser.NodeToTasks(rootNode, &tasksToSave)

	if err != nil {
		log.Printf("Ошибка при обходе дерева выражения и создании задач: %v", err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal error during task generation")
		return
	}

	log.Printf("Выражение успешно спарсено и сформировано %d задач.", len(tasksToSave))
	log.Printf("Конечный результат выражения представлен ID задачи или значением: %s", finalResultIDOrValue)

	// 4. Генерируем уникальный ID для выражения.
	expressionID := uuid.New().String() // Используем библиотеку uuid для генерации ID

	// 5. Сохраняем выражение в базу данных.
	insertExpressionSQL := `INSERT INTO expressions (id, user_id, expression_string, status, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`
	expressionStatus := "Pending" // Начальный статус выражения.

	_, err = s.DB.Exec(insertExpressionSQL, expressionID, userID, req.Expression, expressionStatus)
	if err != nil {
		log.Printf("Ошибка при сохранении выражения в базу данных (ID: %s, UserID: %d): %v", expressionID, userID, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Failed to save expression")
		return
	}
	log.Printf("Выражение сохранено в БД (ID: %s, UserID: %d)", expressionID, userID)

	// 6. Сохраняем сгенерированные задачи в базу данных, связывая их с выражением.
	insertTaskSQL := `INSERT INTO tasks (id, expression_id, operation, arg1, arg2, status, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	// Проходим по списку задач, которые мы сформировали из дерева.
	for _, task := range tasksToSave {
		// Перед сохранением задачи, связываем ее с ID выражения.
		task.ExpressionID = expressionID // Заполняем поле ExpressionID

		// Сохраняем каждую задачу.
		_, err = s.DB.Exec(insertTaskSQL, task.ID, task.ExpressionID, task.Operation, task.Arg1, task.Arg2, task.Status)
		if err != nil {
			log.Printf("Ошибка при сохранении задачи в базу данных (TaskID: %s, Operation: %s, Args: %s, %s, ExpressionID: %s): %v", task.ID, task.Operation, task.Arg1, task.Arg2, task.ExpressionID, err)
			localHTTP.RespondError(w, http.StatusInternalServerError, "Failed to save tasks")
			return
		}
		log.Printf("Задача сохранена в БД (TaskID: %s, Operation: %s, Args: %s, %s, ExpressionID: %s)", task.ID, task.Operation, task.Arg1, task.Arg2, task.ExpressionID)
	}

	// 7. Отправляем ответ с ID созданного выражения.
	responsePayload := CalculateResponse{ID: expressionID}
	log.Printf("Вычисление выражения запрошено успешно. ID выражения: %s", expressionID)
	localHTTP.RespondJSON(w, http.StatusOK, responsePayload)
}

func (s *APIService) ListExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Вызван ListExpressionsHandler (TODO)")
	w.Write([]byte("List Expressions endpoint (TODO)"))
}

func (s *APIService) GetExpressionHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Вызван GetExpressionHandler (TODO)")
	w.Write([]byte("Get Expression endpoint (TODO)"))
}
