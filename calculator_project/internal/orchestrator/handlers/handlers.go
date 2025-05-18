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
	"github.com/gorilla/mux"
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
	JWTSecret []byte // Секретный ключ для подписи JWT токенов
	// Здесь можно будет добавить другие зависимости, например, менеджер задач и т.д.
}

// NewAPIService: Функция-конструктор для создания нового экземпляра APIService.
func NewAPIService(db *sql.DB, jwtSecret []byte) *APIService {
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

	userID, ok := r.Context().Value(localAuth.UserIDKey).(int64) // localAuth.UserIDKey - это константа из пакета internal/auth
	if !ok {
		log.Println("Handler: UserID не найден в контексте запроса. Запрос не авторизован или проблема middleware.")
		localHTTP.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not found in context")
		return
	}
	log.Printf("Handler: Запрос от пользователя с ID: %d", userID)

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
	parserState := localParser.NewParser(req.Expression)
	rootNode, err := parserState.ParseExpression()
	if err != nil {
		// Если парсер вернул ошибку, отвечаем клиенту
		log.Printf("Ошибка парсинга выражения '%s': %v", req.Expression, err)
		localHTTP.RespondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid expression format: %v", err))
		return // Важно выйти после ответа
	}

	// Проверяем, что после парсинга не осталось необработанных символов
	parserState.SkipSpaces()
	if parserState.Pos < len(parserState.Input) {
		log.Printf("Ошибка парсинга: необработанные символы '%s' в конце выражения", parserState.Input[parserState.Pos:])
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid expression format: unexpected characters at the end")
		return // Важно выйти после ответа
	}

	tasksToSave := []localModels.CalculationTask{}
	// !!! NodeToTasks возвращает ID корневой задачи (или значение числа, если выражение = число) !!!
	finalResultIDOrValue, err := localParser.NodeToTasks(rootNode, &tasksToSave)

	if err != nil {
		log.Printf("Ошибка при обходе дерева выражения и создании задач: %v", err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal error during task generation")
		return
	}

	log.Printf("Выражение успешно спарсено и сформировано %d задач.", len(tasksToSave))
	// Этот лог подтверждает, что RootTaskID получен парсером:
	log.Printf("Конечный результат выражения представлен ID задачи или значением: %s", finalResultIDOrValue)

	// 4. Генерируем уникальный ID для выражения.
	expressionID := uuid.New().String() // Используем библиотеку uuid для генерации ID

	// 5. Сохраняем выражение в базу данных.
	// !!! ЭТОТ SQL ЗАПРОС ДОЛЖЕН ВКЛЮЧАТЬ root_task_id !!!
	insertExpressionSQL := `INSERT INTO expressions (id, user_id, expression_string, status, root_task_id, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	expressionStatus := "Pending" // Начальный статус выражения.

	// !!! ЭТОТ ВЫЗОВ EXEC ДОЛЖЕН ПЕРЕДАВАТЬ finalResultIDOrValue ДЛЯ колонки root_task_id !!!
	_, err = s.DB.Exec(insertExpressionSQL, expressionID, userID, req.Expression, expressionStatus, finalResultIDOrValue)
	if err != nil {
		log.Printf("Ошибка при сохранении выражения в базу данных (ID: %s, UserID: %d): %v", expressionID, userID, err)
		// В более надежной системе здесь нужно подумать о транзакциях.
		localHTTP.RespondError(w, http.StatusInternalServerError, "Failed to save expression")
		return
	}
	// Добавлен лог, чтобы увидеть, что именно сохраняется в root_task_id
	log.Printf("Выражение сохранено в БД (ID: %s, UserID: %d, RootTaskID: %s)", expressionID, userID, finalResultIDOrValue)

	// 6. Сохраняем сгенерированные задачи в базу данных, связывая их с выражением.
	insertTaskSQL := `INSERT INTO tasks (id, expression_id, operation, arg1, arg2, status, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	for _, task := range tasksToSave {
		task.ExpressionID = expressionID // Связываем задачу с выражением

		_, err = s.DB.Exec(insertTaskSQL, task.ID, task.ExpressionID, task.Operation, task.Arg1, task.Arg2, task.Status)
		if err != nil {
			log.Printf("Ошибка при сохранении задачи в базу данных (TaskID: %s, Operation: %s, Args: %s, %s, ExpressionID: %s): %v", task.ID, task.Operation, task.Arg1, task.Arg2, task.ExpressionID, err)
			// Важно: Если сохранение задачи провалилось, мы должны пометить ВЫРАЖЕНИЕ как Failed.
			// В более надежной системе здесь нужно начать транзакцию для CalculateHandler,
			// откатывать ее и обновлять статус выражения на Failed при любой ошибке после парсинга.
			// Пока для простоты просто логируем и возвращаем ошибку.
			localHTTP.RespondError(w, http.StatusInternalServerError, "Failed to save task")
			return // Выходим, т.к. не смогли сохранить все задачи
		}
		log.Printf("Задача сохранена в БД (TaskID: %s, Operation: %s, Args: %s, %s, ExpressionID: %s)", task.ID, task.Operation, task.Arg1, task.Arg2, task.ExpressionID)
	}

	// 7. Отправляем ответ с ID созданного выражения.
	responsePayload := CalculateResponse{ID: expressionID}
	log.Printf("Вычисление выражения запрошено успешно. ID выражения: %s", expressionID)
	localHTTP.RespondJSON(w, http.StatusOK, responsePayload)
}

func (s *APIService) ListExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Вызван ListExpressionsHandler")

	// 1. Получаем ID пользователя из контекста запроса (добавлено AuthMiddleware).
	// Используем вспомогательную функцию GetUserIDFromContext из пакета auth.
	userID, ok := localAuth.GetUserIDFromContext(r.Context()) // <--- Получаем UserID из контекста
	if !ok {
		// Если UserID не найден в контексте, это ошибка middleware или неправильное использование.
		log.Println("ListExpressionsHandler: UserID не найден в контексте запроса.")
		localHTTP.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not found in context")
		return // Обязательно выходим
	}
	log.Printf("ListExpressionsHandler: Запрос списка выражений от пользователя с ID: %d", userID)

	// 2. Выбираем все выражения для данного пользователя из базы данных.
	// Сортируем по дате создания, чтобы видеть последние сверху.
	selectExpressionsSQL := `
		SELECT id, user_id, expression_string, status, root_task_id, result, error_message, created_at, updated_at
		FROM expressions
		WHERE user_id = ?
		ORDER BY created_at DESC`

	// Выполняем запрос к базе данных.
	// Используем QueryContext для возможности отмены запроса, передавая контекст запроса.
	rows, err := s.DB.QueryContext(r.Context(), selectExpressionsSQL, userID)
	if err != nil {
		log.Printf("ListExpressionsHandler: Ошибка при выборке выражений для пользователя %d из БД: %v", userID, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Ошибка сервера при получении списка выражений")
		return
	}
	defer rows.Close() // Важно закрыть набор результатов после использования

	// 3. Сканируем результаты запроса в список структур Expression.
	expressions := []localModels.Expression{} // Слайс для хранения выражений

	for rows.Next() {
		var expr localModels.Expression // Переменная для сканирования текущей строки выражения
		// Используем sql.NullString для сканирования nullable полей (result, error_message).
		// Твоя структура Expression имеет Result как sql.NullString - это нужно учесть при сканировании.
		// ОШИБКА в моей Expression структуре выше, Result должен быть sql.NullFloat64!
		// Давай исправим мою структуру Expression в models.go.
		// Исходя из твоего models.go, Expression.FinalResult - sql.NullString. Ок, используем это.

		// Сканируем данные из строки БД в структуру Expression.
		// Убедись, что порядок полей соответствует SELECT запросу.
		// NOTE: Expression.FinalResult у тебя sql.NullString, а не sql.NullFloat64. Сканируем в него.
		// В SQL у тебя колонка 'result' REAL NULL. Сканировать REAL NULL в sql.NullString - НЕПРАВИЛЬНО.
		// Это приведет к ошибке сканирования!
		// Expression.FinalResult ДОЛЖЕН быть sql.NullFloat64 или sql.NullString, но в базе 'result' - REAL.
		// Если в БД 'result' REAL NULL, а в Go struct Expression.FinalResult sql.NullString,
		// нужно или поменять тип в SQL, или поменять тип в Go struct, или сканировать в sql.NullFloat64
		// и затем преобразовывать.
		// Давай предположим, что в твоем models.go, Expression.FinalResult - sql.NullFloat64.
		// ИЛИ что ты готов поменять его на sql.NullFloat64. ИЛИ что в БД 'result' на самом деле TEXT NULL.
		// Исходя из твоего models.go, Expression.FinalResult - sql.NullString.
		// Но в SQL схеме, которую мы делали, 'result' в expressions был REAL NULL.
		// Это несоответствие!
		// Для 'result' (который REAL) нужно использовать sql.NullFloat64 в Go struct.
		// А для error_message (TEXT) - sql.NullString.

		// ВАЖНО: Исходя из твоего models.go (Expression): FinalResult sql.NullString, ErrorMessage sql.NullString.
		// В SQL схеме (expressions): result REAL NULL, error_message TEXT NULL.
		// Это НЕПРАВИЛЬНОЕ СООТВЕТСТВИЕ ТИПОВ!
		// REAL в SQL нужно сканировать в sql.NullFloat64 в Go.
		// TEXT в SQL нужно сканировать в sql.NullString в Go.
		// Тебе нужно исправить struct Expression в models.go:
		// FinalResult sql.NullFloat64
		// ErrorMessage sql.NullString

		// ПРЕДПОЛАГАЕМ, что ты исправил Expression.FinalResult на sql.NullFloat64 в models.go:
		// Тогда сканируем так:
		err := rows.Scan(
			&expr.ID,
			&expr.UserID,
			&expr.ExpressionString,
			&expr.Status,
			&expr.RootTaskID,   // <--- Сканируем root_task_id сюда (sql.NullString)
			&expr.FinalResult,  // <--- Сканируем result сюда (sql.NullFloat64)
			&expr.ErrorMessage, // <--- Сканируем error_message сюда (sql.NullString)
			&expr.CreatedAt,
			&expr.UpdatedAt,
		)
		if err != nil {
			log.Printf("ListExpressionsHandler: Ошибка сканирования строки выражения для пользователя %d: %v", userID, err)
			// Продолжаем сканировать другие строки, но логируем ошибку.
			continue
		}

		// Добавляем отсканированное выражение в список.
		expressions = append(expressions, expr)
	}

	// Проверяем ошибки, которые могли возникнуть при обходе строк (rows.Err()).
	if err := rows.Err(); err != nil {
		log.Printf("ListExpressionsHandler: Ошибка после обхода выражений для пользователя %d: %v", userID, err)
		// Это ошибка при чтении из набора результатов, может указывать на проблему с БД.
		localHTTP.RespondError(w, http.StatusInternalServerError, "Ошибка сервера при получении списка выражений после выборки")
		return
	}

	// 4. Отправляем список выражений в формате JSON.
	// При кодировании в JSON, sql.NullFloat64 и sql.NullString с Valid=false будут преобразованы в null JSON.
	localHTTP.RespondJSON(w, http.StatusOK, expressions)

	log.Printf("ListExpressionsHandler: Успешно отправлен список из %d выражений для пользователя %d", len(expressions), userID)
}

// GetExpressionHandler: Обработчик HTTP-запросов на получение деталей одного выражения пользователя по ID.
// GET /api/v1/expressions/{id}
// Должен быть защищен AuthMiddleware.
// TODO: Реализовать GetExpressionHandler
type ExpressionDetailsResponse struct {
	localModels.Expression                               // Встраиваем структуру Expression
	Tasks                  []localModels.CalculationTask `json:"tasks"` // Список задач выражения
}

// GetExpressionHandler: Обработчик HTTP-запросов на получение деталей одного выражения пользователя по ID.
// GET /api/v1/expressions/{id}
// Должен быть защищен AuthMiddleware.
func (s *APIService) GetExpressionHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Вызван GetExpressionHandler")

	// 1. Получаем ID выражения из URL (из переменной пути).
	// Используем пакет gorilla/mux для извлечения переменных пути.
	vars := mux.Vars(r) // <--- Используем mux.Vars для получения {id}
	expressionID := vars["id"]

	if expressionID == "" {
		log.Println("GetExpressionHandler: ID выражения не указан в URL.")
		localHTTP.RespondError(w, http.StatusBadRequest, "Expression ID is required")
		return
	}

	_, err := uuid.Parse(expressionID)
	if err != nil {
		log.Printf("GetExpressionHandler: Невалидный формат UUID для ID выражения: %s. Ошибка: %v", expressionID, err)
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid expression ID format")
		return // Важно выйти из функции после отправки ошибки
	}

	log.Printf("GetExpressionHandler: Запрос деталей выражения с ID: %s", expressionID)

	// 2. Получаем ID пользователя из контекста запроса (добавлено AuthMiddleware).
	userID, ok := localAuth.GetUserIDFromContext(r.Context())
	if !ok {
		log.Println("GetExpressionHandler: UserID не найден в контексте запроса.")
		localHTTP.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not found in context")
		return // Обязательно выходим
	}
	log.Printf("GetExpressionHandler: Запрос от пользователя с ID: %d", userID)

	// 3. Выбираем выражение из базы данных по его ID И ID пользователя.
	// Это гарантирует, что пользователь может получить доступ только к СВОИМ выражениям.
	selectExpressionSQL := `
        SELECT id, user_id, expression_string, status, result, error_message, created_at, updated_at
        FROM expressions
        WHERE id = ? AND user_id = ?`

	var expr localModels.Expression // Переменная для хранения данных выражения

	// Выполняем запрос. Используем QueryRowContext для выборки одной строки.
	// Убедись, что в твоем models.go Expression.FinalResult - sql.NullFloat64, а ErrorMessage - sql.NullString
	err = s.DB.QueryRowContext(r.Context(), selectExpressionSQL, expressionID, userID).Scan( // <--- Передаем оба ID в запрос
		&expr.ID,
		&expr.UserID,
		&expr.ExpressionString,
		&expr.Status,
		&expr.FinalResult,  // sql.NullFloat64
		&expr.ErrorMessage, // sql.NullString
		&expr.CreatedAt,
		&expr.UpdatedAt,
	)

	// Обрабатываем ошибки выборки выражения.
	if err != nil {
		if err == sql.ErrNoRows {
			// Если выражение с таким ID и UserID не найдено.
			log.Printf("GetExpressionHandler: Выражение с ID %s для пользователя %d не найдено.", expressionID, userID)
			// Возвращаем 404 Not Found.
			localHTTP.RespondError(w, http.StatusNotFound, fmt.Sprintf("Expression with ID %s not found for this user", expressionID))
			return
		}
		// Если произошла другая ошибка базы данных.
		log.Printf("GetExpressionHandler: Ошибка при выборке выражения с ID %s для пользователя %d из БД: %v", expressionID, userID, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Ошибка сервера при получении деталей выражения")
		return
	}

	// Если выражение успешно найдено.
	// 4. Выбираем все задачи, связанные с этим выражением.
	selectTasksSQL := `
		SELECT id, expression_id, operation, arg1, arg2, status, result, error_message, created_at, updated_at
		FROM tasks
		WHERE expression_id = ?` // <--- Выбираем задачи по ID выражения

	// Выполняем запрос к базе данных для задач.
	rows, err := s.DB.QueryContext(r.Context(), selectTasksSQL, expressionID)
	if err != nil {
		log.Printf("GetExpressionHandler: Ошибка при выборке задач для выражения %s из БД: %v", expressionID, err)
		// Возвращаем ошибку сервера, но выражение само найдено.
		localHTTP.RespondError(w, http.StatusInternalServerError, "Ошибка сервера при получении задач выражения")
		return
	}
	defer rows.Close() // Закрываем набор результатов

	// 5. Сканируем результаты запроса задач в список структур CalculationTask.
	tasks := []localModels.CalculationTask{} // Слайс для хранения задач

	for rows.Next() {
		var task localModels.CalculationTask // Переменная для сканирования текущей строки задачи
		// Сканируем данные в структуру CalculationTask.
		// Убедись, что поля Result (sql.NullFloat64) и ErrorMessage (sql.NullString) сканируются корректно.
		err := rows.Scan(
			&task.ID,
			&task.ExpressionID,
			&task.Operation,
			&task.Arg1,
			&task.Arg2,
			&task.Status,
			&task.Result,       // sql.NullFloat64
			&task.ErrorMessage, // sql.NullString
			&task.CreatedAt,
			&task.UpdatedAt,
		)
		if err != nil {
			log.Printf("GetExpressionHandler: Ошибка сканирования строки задачи для выражения %s: %v", expressionID, err)
			// Продолжаем сканировать другие задачи, но логируем ошибку.
			continue
		}
		// Добавляем отсканированную задачу в список.
		tasks = append(tasks, task)
	}

	// Проверяем ошибки после обхода строк задач.
	if err := rows.Err(); err != nil {
		log.Printf("GetExpressionHandler: Ошибка после обхода задач для выражения %s: %v", expressionID, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Ошибка сервера при получении задач выражения после выборки")
		return
	}

	// 6. Собираем ответную структуру и отправляем ее в формате JSON.
	responsePayload := localModels.ExpressionDetailsResponse{
		Expression: expr,
		Tasks:      tasks,
	}

	localHTTP.RespondJSON(w, http.StatusOK, responsePayload)

	log.Printf("GetExpressionHandler: Успешно отправлены детали выражения %s для пользователя %d (наидено %d задач)", expressionID, userID, len(tasks))
}
