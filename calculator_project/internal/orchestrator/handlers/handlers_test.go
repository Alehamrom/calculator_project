package handlers // Файл тестов находится в том же пакете 'handlers'

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	localAuth "calculator_project/internal/auth"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	localModels "calculator_project/internal/models"
	localParser "calculator_project/internal/parser"
)

// testAuthMiddleware: Простая middleware для тестирования, которая добавляет хардкоженый UserID в контекст.
func testAuthMiddleware(userID int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Создаем новый контекст, добавляя UserID к существующему контексту запроса.
		ctx := localAuth.ContextWithUserID(r.Context(), userID)
		// Вызываем следующий handler (наш GetExpressionHandler) с обновленным контекстом.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// setupTestDB: Вспомогательная функция для создания мокированной базы данных
func setupTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New() // Создаем мок базы данных
	if err != nil {
		t.Fatalf("ошибка при создании мока базы данных: %v", err)
	}
	return db, mock
}

// TestRegisterHandler_Success: Тест успешной регистрации пользователя.
func TestRegisterHandler_Success(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close() // Не забываем закрыть мок БД после теста

	// Создаем экземпляр нашего сервиса с мокированной БД и тестовым JWT секретом.
	jwtSecret := []byte("test_secret_key") // Тестовый секрет
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса регистрации.
	registerRequest := RegisterRequest{
		Login:    "testuser",
		Password: "password123",
	}
	requestBody, _ := json.Marshal(registerRequest) // Сериализуем структуру в JSON байты

	// Имитируем ожидаемый SQL INSERT запрос.
	// Обрати внимание: мок ожидает ЛЮБОЙ пароль (т.к. bcrypt генерирует разный хэш),
	// поэтому мы используем sqlmock.AnyArg(). Для логина ожидаем конкретное значение.
	mock.ExpectExec("INSERT INTO users").WithArgs(registerRequest.Login, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1)) // Имитируем успешное выполнение запроса (вставлена 1 строка с ID 1)

	// 2. Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(requestBody))
	rr := httptest.NewRecorder() // ResponseRecorder записывает ответ сервера

	// Вызываем наш обработчик.
	apiService.RegisterHandler(rr, req)

	// 3. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusOK, rr.Code, "Статус код должен быть 200 OK при успешной регистрации")

	// Проверяем, что тело ответа пустое JSON-объектом ({}).
	expectedBody := "{}"
	assert.Equal(t, expectedBody, strings.TrimSpace(rr.Body.String()), "Тело ответа должно быть пустым JSON-объектом")

	// Проверяем, что все ожидания мока БД были выполнены (т.е. INSERT был вызван).
	err := mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")

}

// TestRegisterHandler_DuplicateLogin: Тест регистрации с уже существующим логином.
func TestRegisterHandler_DuplicateLogin(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key") // Тестовый секрет
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса регистрации (логин, который уже существует).
	registerRequest := RegisterRequest{
		Login:    "existinguser", // Логин, который имитирует уже существующий
		Password: "newpassword",
	}
	requestBody, _ := json.Marshal(registerRequest)

	mock.ExpectExec("INSERT INTO users").WithArgs(registerRequest.Login, sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("UNIQUE constraint failed: users.login")) // Имитируем ошибку БД

	// 2. Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(requestBody))
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.RegisterHandler(rr, req)

	// 3. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusConflict, rr.Code, "Статус код должен быть 409 Conflict при регистрации существующего логина")

	// Опционально: Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Login already exists", errorResponse["error"], "Сообщение об ошибке должно указывать на существующий логин")

	// Проверяем, что все ожидания мока БД были выполнены.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestLoginHandler_Success: Тест успешного входа пользователя.
func TestLoginHandler_Success(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса с тестовым JWT секретом.
	jwtSecret := []byte("very_secret_test_key_for_jwt") // Используем тот же тестовый секрет, что и в auth_test.go
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса входа.
	loginRequest := LoginRequest{
		Login:    "existinguser",
		Password: "correctpassword",
	}
	requestBody, _ := json.Marshal(loginRequest)

	// Генерируем ожидаемый хэш пароля для мока БД.
	// Мы используем ту же функцию хеширования, что и в RegisterHandler и auth_test.go.
	hashedPassword, err := localAuth.HashPassword(loginRequest.Password)
	assert.NoError(t, err, "Не удалось хешировать пароль для теста") // Убеждаемся, что хеширование для теста прошло успешно

	// ID пользователя, который будет возвращен моком БД.
	expectedUserID := int64(42) // Произвольный тестовый ID пользователя

	// Имитируем ожидаемый SQL SELECT запрос для поиска пользователя по логину.
	// Мок должен вернуть одну строку с ID, логином и ПРЕДВАРИТЕЛЬНО СГЕНЕРИРОВАННЫМ хэшем пароля.
	rows := sqlmock.NewRows([]string{"id", "login", "password_hash"}).
		AddRow(expectedUserID, loginRequest.Login, hashedPassword) // Возвращаем строку с данными пользователя

	mock.ExpectQuery("SELECT id, login, password_hash FROM users WHERE login = ?").WithArgs(loginRequest.Login).
		WillReturnRows(rows) // Мок должен вернуть подготовленную строку

	// 2. Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(requestBody))
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.LoginHandler(rr, req)

	// 3. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusOK, rr.Code, "Статус код должен быть 200 OK при успешном входе")

	// Проверяем тело ответа. Ожидаем JSON с полем "token" (не пустым).
	var loginResponse LoginResponse
	err = json.Unmarshal(rr.Body.Bytes(), &loginResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.NotEmpty(t, loginResponse.Token, "В ответе должен быть непустой JWT токен")

	// Опционально: Проверяем, что сгенерированный токен валиден и содержит правильный UserID.
	// Это дублирует часть логики ValidateJWT, но полезно для end-to-end проверки в рамках этого обработчика.
	validatedUserID, validateErr := localAuth.ValidateJWT(loginResponse.Token, apiService.JWTSecret)
	assert.NoError(t, validateErr, "Сгенерированный токен должен быть валидным")
	assert.Equal(t, expectedUserID, validatedUserID, "UserID в токене должен соответствовать ID пользователя")

	// Проверяем, что все ожидания мока БД были выполнены (SELECT был вызван).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

func TestLoginHandler_IncorrectPassword(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key") // Секрет не используется при проверке пароля, но нужен для создания APIService
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса входа (существующий пользователь, но неправильный пароль).
	loginRequest := LoginRequest{
		Login:    "existinguser",
		Password: "wrongpassword", // Неправильный пароль
	}
	requestBody, _ := json.Marshal(loginRequest)

	// Генерируем хэш ПРАВИЛЬНОГО пароля, который находится в моке БД.
	// Обработчик сравнит "wrongpassword" с этим хэшем, и CheckPasswordHash вернет false.
	correctHashedPassword, err := localAuth.HashPassword("correctpassword") // Хэш верного пароля из "БД"
	assert.NoError(t, err, "Не удалось хешировать правильный пароль для теста")

	// ID пользователя, который будет возвращен моком БД.
	expectedUserID := int64(42)

	// Имитируем ожидаемый SQL SELECT запрос для поиска пользователя по логину.
	// Мок должен вернуть строку с данными пользователя и хэшем ПРАВИЛЬНОГО пароля.
	rows := sqlmock.NewRows([]string{"id", "login", "password_hash"}).
		AddRow(expectedUserID, loginRequest.Login, correctHashedPassword) // Возвращаем данные пользователя с правильным хэшем

	mock.ExpectQuery("SELECT id, login, password_hash FROM users WHERE login = ?").WithArgs(loginRequest.Login).
		WillReturnRows(rows) // Мок должен вернуть подготовленную строку

	// 2. Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(requestBody))
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.LoginHandler(rr, req)

	// 3. Проверки: Проверяем статус код ответа.
	// Ожидаем 401 Unauthorized, потому что пароль неверный.
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Статус код должен быть 401 Unauthorized при неверном пароле")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
	var errorResponse map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Invalid login or password", errorResponse["error"], "Сообщение об ошибке должно указывать на неверные данные")

	// Проверяем, что все ожидания мока БД были выполнены (SELECT был вызван).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestLoginHandler_UserNotFound: Тест входа для несуществующего пользователя.
func TestLoginHandler_UserNotFound(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key") // Секрет не используется в этом сценарии
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса входа (логин, которого нет в БД).
	loginRequest := LoginRequest{
		Login:    "nonexistentuser", // Логин, которого нет
		Password: "anypassword",
	}
	requestBody, _ := json.Marshal(loginRequest)

	// Имитируем ожидаемый SQL SELECT запрос для поиска пользователя по логину.
	// Мок должен вернуть ошибку sql.ErrNoRows, имитируя отсутствие пользователя в БД.
	mock.ExpectQuery("SELECT id, login, password_hash FROM users WHERE login = ?").WithArgs(loginRequest.Login).
		WillReturnError(sql.ErrNoRows) // Мок возвращает ошибку "строка не найдена"

	// 2. Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(requestBody))
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.LoginHandler(rr, req)

	// 3. Проверки: Проверяем статус код ответа.
	// Ожидаем 401 Unauthorized, как и для неверного пароля (для безопасности не сообщаем клиенту, что логин существует).
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Статус код должен быть 401 Unauthorized для несуществующего пользователя")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Invalid login or password", errorResponse["error"], "Сообщение об ошибке должно указывать на неверные данные")

	// Проверяем, что все ожидания мока БД были выполнены (SELECT был вызван).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestLoginHandler_EmptyInput: Тест входа с пустым логином или паролем.
func TestLoginHandler_EmptyInput(t *testing.T) {
	// Подготовка: Создаем мок базы данных и сервис.
	// Мок БД не должен использоваться в этом тесте.
	db, mock := setupTestDB(t)
	defer db.Close()

	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// Определяем тестовые случаи для разных комбинаций пустых полей.
	testCases := []struct {
		name          string
		loginReq      LoginRequest
		expectedError string
	}{
		{
			name: "EmptyLogin",
			loginReq: LoginRequest{
				Login:    "", // Пустой логин
				Password: "anypassword",
			},
			expectedError: "Login and password cannot be empty",
		},
		{
			name: "EmptyPassword",
			loginReq: LoginRequest{
				Login:    "anyuser",
				Password: "", // Пустой пароль
			},
			expectedError: "Login and password cannot be empty",
		},
		{
			name: "EmptyLoginAndPassword",
			loginReq: LoginRequest{
				Login:    "", // Пустой логин
				Password: "", // Пустой пароль
			},
			expectedError: "Login and password cannot be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) { // Используем t.Run для запуска под-тестов с разными данными
			requestBody, _ := json.Marshal(tc.loginReq)

			// Выполнение: Создаем тестовый HTTP запрос и ResponseRecorder.
			req := httptest.NewRequest("POST", "/login", bytes.NewReader(requestBody))
			rr := httptest.NewRecorder()

			// Вызываем наш обработчик.
			apiService.LoginHandler(rr, req)

			// Проверки: Проверяем статус код ответа.
			assert.Equal(t, http.StatusBadRequest, rr.Code, "Статус код должен быть 400 Bad Request при пустых полях")

			// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
			var errorResponse map[string]string
			err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
			assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
			assert.Equal(t, tc.expectedError, errorResponse["error"], "Сообщение об ошибке должно соответствовать ожидаемому")

			// Проверяем, что никаких запросов к моку БД НЕ БЫЛО.
			err = mock.ExpectationsWereMet() // Если обработчик попытался обратиться к БД, этот вызов упадет
			assert.NoError(t, err, "Обработчик не должен обращаться к базе данных при пустых полях")
		})
	}
}
func TestCalculateHandler_Success(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса. JWT Secret здесь не используется напрямую в CalculateHandler,
	// но нужен для создания APIService.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя, который будет "аутентифицирован" (помещен в контекст).
	authenticatedUserID := int64(101) // Произвольный тестовый ID пользователя

	// Данные для запроса вычисления.
	calculateRequest := CalculateRequest{
		Expression: "2+2*2", // Простое выражение
	}
	requestBody, _ := json.Marshal(calculateRequest)

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	// Создаем контекст с UserID.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID) // Используем вспомогательную функцию из auth
	// Создаем запрос с этим контекстом.
	req := httptest.NewRequest("POST", "/calculate", bytes.NewReader(requestBody))
	req = req.WithContext(ctx) // Привязываем контекст к запросу

	// 3. Имитируем ожидания мока БД.

	// Запускаем парсер для получения ожидаемых задач и корня выражения.
	parserState := localParser.NewParser(calculateRequest.Expression)
	rootNode, err := parserState.ParseExpression()
	assert.NoError(t, err, "Парсер не должен возвращать ошибку для валидного выражения")

	tasksToSave := []localModels.CalculationTask{}
	_, err = localParser.NodeToTasks(rootNode, &tasksToSave)
	assert.NoError(t, err, "NodeToTasks не должен возвращать ошибку для валидного выражения")

	// Ожидаем INSERT в таблицу expressions.
	// root_task_id должен быть finalResultIDOrValue.
	mock.ExpectExec("INSERT INTO expressions").
		WithArgs(sqlmock.AnyArg(), authenticatedUserID, calculateRequest.Expression, "Pending", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1)) // Успешная вставка выражения

	// Ожидаем INSERT для каждой задачи.
	insertTaskSQL := "INSERT INTO tasks" // Часть запроса для ExpectExec
	for _, task := range tasksToSave {
		arg1Expect := interface{}(task.Arg1)
		if _, err := uuid.Parse(task.Arg1); err == nil {
			arg1Expect = sqlmock.AnyArg() // Если это валидный UUID, ожидаем AnyArg (уже присваивается interface{})
		}

		arg2Expect := interface{}(task.Arg2)
		if _, err := uuid.Parse(task.Arg2); err == nil {
			arg2Expect = sqlmock.AnyArg() // Если это валидный UUID, ожидаем AnyArg (уже присваивается interface{})
		}

		mock.ExpectExec(insertTaskSQL).
			// Ожидаем: ID задачи (AnyArg), ID выражения (AnyArg), Операция (точно), Arg1 (точно или AnyArg), Arg2 (точно или AnyArg), Статус (точно)
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), task.Operation, arg1Expect, arg2Expect, "Pending").
			WillReturnResult(sqlmock.NewResult(1, 1)) // Успешная вставка задачи

	}

	// 4. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.CalculateHandler(rr, req)

	// 5. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusOK, rr.Code, "Статус код должен быть 200 OK при успешном запросе вычисления")

	// Проверяем тело ответа. Ожидаем JSON с полем "id" (не пустым - ID выражения).
	var calculateResponse CalculateResponse
	err = json.Unmarshal(rr.Body.Bytes(), &calculateResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.NotEmpty(t, calculateResponse.ID, "В ответе должен быть непустой ID выражения")

	// Проверяем, что все ожидания мока БД были выполнены.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestCalculateHandler_InvalidExpression: Тест запроса на вычисление с некорректным выражением.
func TestCalculateHandler_InvalidExpression(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	// В этом тесте обращение к БД не должно происходить, так как парсер вернет ошибку раньше.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя (нужен для контекста, хотя до логики с UserID в этом сценарии не дойдет).
	authenticatedUserID := int64(102) // Другой тестовый ID

	// Данные для запроса вычисления с НЕКОРРЕКТНЫМ выражением.
	calculateRequest := CalculateRequest{
		Expression: "2 + * 2", // Некорректное выражение
	}
	requestBody, _ := json.Marshal(calculateRequest)

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("POST", "/calculate", bytes.NewReader(requestBody))
	req = req.WithContext(ctx) // Привязываем контекст к запросу

	// В этом тесте мы НЕ настраиваем ожидания мока БД,
	// потому что обработчик должен завершиться с ошибкой парсинга ДО обращения к БД.

	// 3. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.CalculateHandler(rr, req)

	// 4. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusBadRequest, rr.Code, "Статус код должен быть 400 Bad Request при некорректном выражении")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке парсинга.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	// Проверяем, что сообщение об ошибке содержит информацию о неверном формате.
	assert.Contains(t, errorResponse["error"], "Invalid expression format", "Сообщение об ошибке должно указывать на неверный формат выражения")

	// Проверяем, что никаких запросов к моку БД НЕ БЫЛО.
	// mock.ExpectationsWereMet() здесь вызовет ошибку, если что-то ожидалось, но не произошло.
	// Поскольку мы ничего не ожидали, эта проверка убедится, что Exec/Query не были вызваны.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Обработчик не должен обращаться к базе данных при некорректном выражении")
}

// TestCalculateHandler_EmptyExpression: Тест запроса на вычисление с пустым выражением.
func TestCalculateHandler_EmptyExpression(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	// В этом тесте обращение к БД не должно происходить.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя (нужен для контекста, но до логики с UserID здесь не дойдет).
	authenticatedUserID := int64(103) // Другой тестовый ID

	// Данные для запроса вычисления с ПУСТЫМ выражением.
	calculateRequest := CalculateRequest{
		Expression: "", // Пустое выражение
	}
	requestBody, _ := json.Marshal(calculateRequest)

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("POST", "/calculate", bytes.NewReader(requestBody))
	req = req.WithContext(ctx) // Привязываем контекст к запросу

	// В этом тесте мы НЕ настраиваем ожидания мока БД,
	// потому что обработчик должен завершиться с ошибкой валидации ДО обращения к БД.

	// 3. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.CalculateHandler(rr, req)

	// 4. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusBadRequest, rr.Code, "Статус код должен быть 400 Bad Request при пустом выражении")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке валидации.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Expression cannot be empty", errorResponse["error"], "Сообщение об ошибке должно указывать на пустое выражение")

	// Проверяем, что никаких запросов к моку БД НЕ БЫЛО.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Обработчик не должен обращаться к базе данных при пустом выражении")

}

// TestCalculateHandler_UserIDMissingFromContext: Тест запроса на вычисление при отсутствии UserID в контексте.
// Это имитирует ситуацию, когда AuthMiddleware не сработал или был пропущен.
func TestCalculateHandler_UserIDMissingFromContext(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	// В этом тесте обращение к БД не должно происходить.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// Данные для запроса вычисления (содержание неважно, т.к. ошибка будет раньше).
	calculateRequest := CalculateRequest{
		Expression: "1+1",
	}
	requestBody, _ := json.Marshal(calculateRequest)

	// 2. Создаем HTTP запрос БЕЗ добавления UserID в контекст.
	// Имитируем запрос, который НЕ прошел через успешный AuthMiddleware.
	req := httptest.NewRequest("POST", "/calculate", bytes.NewReader(requestBody))
	// Мы НЕ вызываем req = req.WithContext(...) с контекстом, содержащим UserID.

	// В этом тесте мы НЕ настраиваем ожидания мока БД.

	// 3. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.CalculateHandler(rr, req)

	// 4. Проверки: Проверяем статус код ответа.
	// Обработчик должен вернуть 401 Unauthorized, если UserID не найден.
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Статус код должен быть 401 Unauthorized, если UserID отсутствует в контексте")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Unauthorized: User ID not found in context", errorResponse["error"], "Сообщение об ошибке должно указывать на отсутствие UserID")

	// Проверяем, что никаких запросов к моку БД НЕ БЫЛО.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Обработчик не должен обращаться к базе данных, если UserID отсутствует")
}

// TestCalculateHandler_DatabaseErrorOnExpressionInsert: Тест запроса на вычисление при ошибке вставки выражения в БД.
func TestCalculateHandler_DatabaseErrorOnExpressionInsert(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя (нужен для контекста).
	authenticatedUserID := int64(104) // Другой тестовый ID

	// Данные для запроса вычисления (валидное выражение).
	calculateRequest := CalculateRequest{
		Expression: "3*3+1", // Валидное выражение
	}
	requestBody, _ := json.Marshal(calculateRequest)

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("POST", "/calculate", bytes.NewReader(requestBody))
	req = req.WithContext(ctx) // Привязываем контекст к запросу

	// 3. Имитируем ожидания мока БД.
	// Парсер должен успешно обработать выражение.
	parserState := localParser.NewParser(calculateRequest.Expression)
	rootNode, err := parserState.ParseExpression()
	assert.NoError(t, err, "Парсер не должен возвращать ошибку для валидного выражения")

	tasksToSave := []localModels.CalculationTask{}
	_, err = localParser.NodeToTasks(rootNode, &tasksToSave) // Используем _ для игнорирования finalResultIDOrValue
	assert.NoError(t, err, "NodeToTasks не должен возвращать ошибку для валидного выражения")

	// Ожидаем INSERT в таблицу expressions.
	// Но на этот раз мок должен вернуть ОШИБКУ.
	expectedDBError := errors.New("simulated database error on expression insert") // Имитируем ошибку БД
	mock.ExpectExec("INSERT INTO expressions").
		WithArgs(sqlmock.AnyArg(), authenticatedUserID, calculateRequest.Expression, "Pending", sqlmock.AnyArg()).
		WillReturnError(expectedDBError)

	// Мы НЕ настраиваем ожидания для INSERT в таблицу tasks,
	// потому что обработчик должен остановить выполнение после ошибки вставки выражения.

	// 4. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.CalculateHandler(rr, req)

	// 5. Проверки: Проверяем статус код ответа.
	// Обработчик должен вернуть 500 Internal Server Error при ошибке БД.
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "Статус код должен быть 500 Internal Server Error при ошибке вставки выражения в БД")

	// Проверяем тело ответа на наличие общего сообщения об ошибке сервера.
	var errorResponse map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Failed to save expression", errorResponse["error"], "Сообщение об ошибке должно указывать на ошибку сохранения выражения")

	// Проверяем, что ожидания мока БД выполнены (т.е. Exec для expressions был вызван,
	// а Exec для tasks - НЕТ).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены (ошибка на вставке выражения)")
}

// TestListExpressionsHandler_Success: Тест успешного получения списка выражений пользователя.
func TestListExpressionsHandler_Success(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key") // Секрет не используется напрямую, но нужен для APIService
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя, для которого запрашиваем список выражений.
	authenticatedUserID := int64(201) // Произвольный тестовый ID пользователя

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("GET", "/expressions", nil) // GET запрос, тело не нужно
	req = req.WithContext(ctx)                             // Привязываем контекст с UserID

	// 3. Имитируем данные, которые вернет база данных.
	expression1 := localModels.Expression{
		ID:               uuid.New().String(),                                      // UUID
		UserID:           authenticatedUserID,                                      // int64
		ExpressionString: "1+1",                                                    // string
		Status:           "Completed",                                              // string
		RootTaskID:       sql.NullString{String: uuid.New().String(), Valid: true}, // sql.NullString (ID задачи)
		FinalResult:      sql.NullFloat64{Float64: 2.0, Valid: true},               // sql.NullFloat64 (результат)
		ErrorMessage:     sql.NullString{Valid: false},                             // sql.NullString (ошибка, null)
		CreatedAt:        time.Now().Add(-time.Hour),                               // time.Time
		UpdatedAt:        time.Now().Add(-time.Minute),                             // time.Time
	}

	expression2 := localModels.Expression{
		ID:               uuid.New().String(),
		UserID:           authenticatedUserID,
		ExpressionString: "2*2",
		Status:           "Pending", // Статус pending
		RootTaskID:       sql.NullString{String: uuid.New().String(), Valid: true},
		FinalResult:      sql.NullFloat64{Valid: false}, // Результат null
		ErrorMessage:     sql.NullString{Valid: false},
		CreatedAt:        time.Now().Add(-30 * time.Minute),
		UpdatedAt:        sql.NullTime{Valid: false}.Time, // UpdatedAt может быть null или иметь Valid=false
	}

	// Исправленные expression2 с учетом time.Time для UpdatedAt
	expression2 = localModels.Expression{
		ID:               uuid.New().String(),
		UserID:           authenticatedUserID,
		ExpressionString: "2*2",
		Status:           "Pending", // Статус pending
		RootTaskID:       sql.NullString{String: uuid.New().String(), Valid: true},
		FinalResult:      sql.NullFloat64{Valid: false}, // Результат null
		ErrorMessage:     sql.NullString{Valid: false},
		CreatedAt:        time.Now().Add(-30 * time.Minute),
		UpdatedAt:        time.Now().Add(-10 * time.Minute),
	}

	// Подготавливаем строки, которые вернет мок БД.
	// Порядок полей ДОЛЖЕН строго соответствовать SELECT запросу в ListExpressionsHandler!
	rows := sqlmock.NewRows([]string{"id", "user_id", "expression_string", "status", "root_task_id", "result", "error_message", "created_at", "updated_at"}).
		AddRow(expression2.ID, expression2.UserID, expression2.ExpressionString, expression2.Status, expression2.RootTaskID, expression2.FinalResult, expression2.ErrorMessage, expression2.CreatedAt, expression2.UpdatedAt).
		AddRow(expression1.ID, expression1.UserID, expression1.ExpressionString, expression1.Status, expression1.RootTaskID, expression1.FinalResult, expression1.ErrorMessage, expression1.CreatedAt, expression1.UpdatedAt)

	mock.ExpectQuery(`^\s*SELECT\s+id,\s*user_id,\s*expression_string,\s*status,\s*root_task_id,\s*result,\s*error_message,\s*created_at,\s*updated_at\s+FROM\s+expressions\s+WHERE\s+user_id\s*=\s*\?\s+ORDER\s+BY\s+created_at\s+DESC\s*$`).
		WithArgs(authenticatedUserID). // Ожидаем, что запрос фильтруется по ID пользователя из контекста
		WillReturnRows(rows)           // Мок вернет подготовленные строки

	// 4. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.ListExpressionsHandler(rr, req)

	// 5. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusOK, rr.Code, "Статус код должен быть 200 OK при успешном получении списка выражений")

	// Проверяем тело ответа. Ожидаем JSON массив выражений.
	var actualExpressions []localModels.Expression // Слайс для десериализации ответа
	err := json.Unmarshal(rr.Body.Bytes(), &actualExpressions)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON массивом выражений")

	// Проверяем, что количество возвращенных выражений соответствует ожидаемому.
	assert.Len(t, actualExpressions, 2, "Должно быть возвращено 2 выражения")

	// Проверяем содержимое возвращенных выражений (можно сравнить с expression1 и expression2).
	// Сравнение целиком может быть сложным из-за полей времени, но можно проверить ключевые поля.
	// Убедимся, что порядок в ответе соответствует ORDER BY в запросе (DESC по created_at).
	// expression2 создано позже expression1, поэтому ожидаем order: expression2, expression1.
	assert.Equal(t, expression2.ID, actualExpressions[0].ID, "Первое выражение в ответе должно быть самым недавним (по CreatedAt)")
	assert.Equal(t, expression1.ID, actualExpressions[1].ID, "Второе выражение в ответе должно быть более старым")

	// Проверяем, что все ожидания мока БД были выполнены (SELECT был вызван).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestListExpressionsHandler_NoExpressions: Тест получения списка выражений, когда у пользователя их нет.
func TestListExpressionsHandler_NoExpressions(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя.
	authenticatedUserID := int64(202) // Другой тестовый ID пользователя

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("GET", "/expressions", nil) // GET запрос
	req = req.WithContext(ctx)                             // Привязываем контекст

	// 3. Имитируем данные, которые вернет база данных: ПУСТОЙ набор строк.
	// Порядок полей должен соответствовать SELECT запросу, но строк не будет.
	rows := sqlmock.NewRows([]string{"id", "user_id", "expression_string", "status", "root_task_id", "result", "error_message", "created_at", "updated_at"}) // Пустой набор строк

	// Имитируем ожидаемый SQL SELECT запрос.
	selectSQLRegexPattern := `^\s*SELECT\s+id,\s*user_id,\s*expression_string,\s+status,\s*root_task_id,\s+result,\s*error_message,\s+created_at,\s+updated_at\s+FROM\s+expressions\s+WHERE\s+user_id\s*=\s*\?\s+ORDER\s+BY\s+created_at\s+DESC\s*$`

	mock.ExpectQuery(selectSQLRegexPattern). // Используем строку регулярного выражения
							WithArgs(authenticatedUserID). // Фильтр по ID пользователя
							WillReturnRows(rows)           // Мок вернет ПУСТОЙ набор строк

	// 4. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.ListExpressionsHandler(rr, req)

	// 5. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusOK, rr.Code, "Статус код должен быть 200 OK, даже если выражений нет")

	// Проверяем тело ответа. Ожидаем ПУСТОЙ JSON массив ([]).
	var actualExpressions []localModels.Expression
	err := json.Unmarshal(rr.Body.Bytes(), &actualExpressions)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON массивом (пустым)")
	assert.Len(t, actualExpressions, 0, "Должен быть возвращен пустой массив")
	assert.Equal(t, "[]", strings.TrimSpace(rr.Body.String()), "Тело ответа должно быть пустым JSON массивом '[]'")

	// Проверяем, что ожидания мока БД были выполнены (SELECT был вызван).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены")
}

// TestListExpressionsHandler_DatabaseError: Тест получения списка выражений при ошибке БД во время выборки.
func TestListExpressionsHandler_DatabaseError(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя.
	authenticatedUserID := int64(203) // Другой тестовый ID пользователя

	// 2. Имитируем работу AuthMiddleware: добавляем UserID в контекст запроса.
	ctx := localAuth.ContextWithUserID(context.Background(), authenticatedUserID)
	req := httptest.NewRequest("GET", "/expressions", nil) // GET запрос
	req = req.WithContext(ctx)                             // Привязываем контекст

	// 3. Имитируем ожидаемый SQL SELECT запрос.
	// Но на этот раз мок должен вернуть ОШИБКУ при выполнении запроса.
	selectSQLRegexPattern := `^\s*SELECT\s+id,\s*user_id,\s*expression_string,\s+status,\s*root_task_id,\s+result,\s*error_message,\s+created_at,\s+updated_at\s+FROM\s+expressions\s+WHERE\s+user_id\s*=\s*\?\s+ORDER\s+BY\s+created_at\s+DESC\s*$`
	expectedDBError := errors.New("simulated database error on select expressions") // Имитируем ошибку БД

	mock.ExpectQuery(selectSQLRegexPattern). // Используем строку регулярного выражения
							WithArgs(authenticatedUserID). // Фильтр по ID пользователя
							WillReturnError(expectedDBError)

	// 4. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.ListExpressionsHandler(rr, req)

	// 5. Проверки: Проверяем статус код ответа.
	// Обработчик должен вернуть 500 Internal Server Error при ошибке БД.
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "Статус код должен быть 500 Internal Server Error при ошибке БД")

	// Проверяем тело ответа на наличие общего сообщения об ошибке сервера.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	assert.Equal(t, "Ошибка сервера при получении списка выражений", errorResponse["error"], "Сообщение об ошибке должно указывать на ошибку получения списка выражений")

	// Проверяем, что ожидание мока БД выполнено (т.е. SELECT был вызван и вернул ошибку).
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Ожидания мока базы данных должны быть выполнены (ошибка на SELECT)")
}

// TestListExpressionsHandler_UserIDMissingFromContext: Тест получения списка выражений при отсутствии UserID в контексте.
// Это имитирует ситуацию, когда AuthMiddleware не сработал или был пропущен.
func TestListExpressionsHandler_UserIDMissingFromContext(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	// В этом тесте обращение к БД не должно происходить.
	db, mock := setupTestDB(t)
	defer db.Close()

	// Создаем экземпляр нашего сервиса.
	jwtSecret := []byte("test_secret_key") // Секрет не используется напрямую
	apiService := NewAPIService(db, jwtSecret)

	// 2. Создаем HTTP запрос БЕЗ добавления UserID в контекст.
	// Имитируем запрос, который НЕ прошел через успешный AuthMiddleware.
	req := httptest.NewRequest("GET", "/expressions", nil) // GET запрос

	// Мы НЕ добавляем UserID в контекст.

	// В этом тесте мы НЕ настраиваем ожидания мока БД.

	// 3. Выполнение: Создаем ResponseRecorder.
	rr := httptest.NewRecorder()

	// Вызываем наш обработчик.
	apiService.ListExpressionsHandler(rr, req)

	// 4. Проверки: Проверяем статус код ответа.
	// Обработчик должен вернуть 401 Unauthorized, если UserID не найден.
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Статус код должен быть 401 Unauthorized, если UserID отсутствует в контексте")

	// Проверяем тело ответа на наличие ожидаемого сообщения об ошибке.
	var errorResponse map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON")
	// Сообщение об ошибке должно совпадать с тем, что возвращает обработчик в handlers.go.
	// В ListExpressionsHandler в случае отсутствия UserID, он должен вернуть то же сообщение, что и CalculateHandler.
	assert.Equal(t, "Unauthorized: User ID not found in context", errorResponse["error"], "Сообщение об ошибке должно указывать на отсутствие UserID")

	// Проверяем, что никаких запросов к моку БД НЕ БЫЛО.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Обработчик не должен обращаться к базе данных, если UserID отсутствует")
}

func TestGetExpressionHandler_Success(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных.
	db, mock := setupTestDB(t)
	defer db.Close() // Закрываем соединение с моком после завершения теста

	// Создаем экземпляр нашего сервиса API.
	jwtSecret := []byte("test_secret_key") // Этот секрет не используется напрямую в этом тесте
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя, который запрашивает выражение.
	// Этот ID будет добавлен в контекст тестовым middleware и использован в ожидании мока БД.
	testUserID := int64(301) // Произвольный тестовый ID пользователя

	// ID выражения, которое запрашиваем (должно принадлежать testUserID).
	requestedExpressionID := uuid.New().String() // Генерируем случайный UUID для ID выражения

	// 2. Имитируем работу роутера и AuthMiddleware: создаем тестовый сервер с роутером и регистрируем handler с тестовым middleware.

	// Создаем реальный (но минимальный) экземпляр mux роутера для теста.
	router := mux.NewRouter()

	// Получаем наш GetExpressionHandler как http.HandlerFunc.
	getExpressionHandler := http.HandlerFunc(apiService.GetExpressionHandler)

	// Оборачиваем GetExpressionHandler в тестовый AuthMiddleware.
	// Middleware добавит testUserID в контекст запроса ПЕРЕД вызовом основного handler'а.
	handlerWithAuth := testAuthMiddleware(testUserID, getExpressionHandler)

	// Регистрируем ОБРАБОТЧИК С MIDDLEWARE на тестовом пути с переменной {id}.
	// Роутер будет парсить путь, testAuthMiddleware добавит UserID, и только потом вызовется GetExpressionHandler.
	router.Handle("/expressions/{id}", handlerWithAuth).Methods("GET")

	// Создаем тестовый HTTP сервер, который будет использовать наш настроенный тестовый роутер.
	testServer := httptest.NewServer(router)
	defer testServer.Close() // Важно закрыть тестовый сервер после завершения теста

	// 3. Имитируем данные, которые вернет база данных (ОДНО выражение).
	// Эти данные будут использоваться для настройки мока ПЕРВОГО запроса (выборки выражения).

	expectedExpression := localModels.Expression{
		ID:               requestedExpressionID, // ID, который мы запросили
		UserID:           testUserID,            // Принадлежит этому пользователю
		ExpressionString: "10/2-1",              // Пример выражения
		Status:           "Completed",           // Пример статуса выполнения
		// RootTaskID не выбирается в этом handler'е, хотя и есть в структуре Expression.
		FinalResult:  sql.NullFloat64{Float64: 4.0, Valid: true}, // Результат вычисления (NotNull)
		ErrorMessage: sql.NullString{Valid: false},               // Нет ошибки (NULL)
		CreatedAt:    time.Now().Add(-2 * time.Hour),             // Время создания
		UpdatedAt:    time.Now().Add(-time.Hour),                 // Время обновления
	}

	// Подготавливаем набор строк, который вернет мок БД (ОДНА строка) для ПЕРВОГО запроса (выражения).
	// Порядок полей в AddRow ДОЛЖЕН СТРОГО соответствовать списку колонок в SELECT запросе в GetExpressionHandler!
	// SELECT id, user_id, expression_string, status, result, error_message, created_at, updated_at
	rows := sqlmock.NewRows([]string{"id", "user_id", "expression_string", "status", "result", "error_message", "created_at", "updated_at"}). // Список колонок
																			AddRow(
			expectedExpression.ID,
			expectedExpression.UserID,
			expectedExpression.ExpressionString,
			expectedExpression.Status,
			expectedExpression.FinalResult,  // Используем sql.NullFloat64
			expectedExpression.ErrorMessage, // Используем sql.NullString
			expectedExpression.CreatedAt,
			expectedExpression.UpdatedAt,
		) // Добавляем одну строку с данными

	// Имитируем ожидаемый SQL SELECT запрос к базе данных для ВЫРАЖЕНИЯ.
	// Используем строку с РЕГУЛЯРНЫМ ВЫРАЖЕНИЕМ для учета возможных вариаций пробелов.
	// Убедись, что этот паттерн ТОЧНО соответствует запросу в GetExpressionHandler.
	selectExpressionSQLPattern := `^\s*SELECT\s+id,\s*user_id,\s*expression_string,\s+status,\s+result,\s*error_message,\s+created_at,\s+updated_at\s+FROM\s+expressions\s+WHERE\s+id\s*=\s*\?\s+AND\s+user_id\s*=\s*\?\s*$`

	// Настраиваем ПЕРВОЕ ожидание мока БД: ожидаем запрос выражения.
	mock.ExpectQuery(selectExpressionSQLPattern). // Ожидаем запрос, соответствующий регулярке
							WithArgs(requestedExpressionID, testUserID). // Ожидаем, что запрос будет с аргументами ID выражения и ID пользователя
							WillReturnRows(rows).                        // Мок вернет подготовленную нами строку выражения
							RowsWillBeClosed()                           // Указываем sqlmock, что после сканирования строки метод Rows.Close() будет вызван (это стандартно для QueryRow)

	// 4. Имитируем данные, которые вернет база данных для ЗАДАЧ выражения.
	// Эти данные будут использоваться для настройки мока ВТОРОГО запроса (выборки задач).

	// Создаем несколько "фейковых" задач для ожидаемого выражения.
	task1 := localModels.CalculationTask{
		ID:           uuid.New().String(),                         // Уникальный ID задачи
		ExpressionID: requestedExpressionID,                       // Связана с запрошенным выражением
		Operation:    "*",                                         // Пример операции
		Arg1:         "10",                                        // Пример аргумента (число)
		Arg2:         "2",                                         // Пример аргумента (число)
		Status:       "Completed",                                 // Пример статуса
		Result:       sql.NullFloat64{Float64: 20.0, Valid: true}, // Результат (заполнено)
		ErrorMessage: sql.NullString{Valid: false},                // Ошибка (NULL)
		CreatedAt:    time.Now().Add(-time.Minute),                // Время создания
		UpdatedAt:    time.Now().Add(-30 * time.Second),           // Время обновления
	}
	task2 := localModels.CalculationTask{
		ID:           uuid.New().String(),
		ExpressionID: requestedExpressionID, // Связана с запрошенным выражением
		Operation:    "-",
		Arg1:         task1.ID, // Аргумент - ID другой задачи (зависимость)
		Arg2:         "1",
		Status:       "Pending",                     // Пример pending задачи
		Result:       sql.NullFloat64{Valid: false}, // Результат (NULL для pending)
		ErrorMessage: sql.NullString{Valid: false},  // Ошибка (NULL)
		CreatedAt:    time.Now().Add(-20 * time.Second),
		UpdatedAt:    sql.NullTime{}.Time, // UpdatedAt может быть нулевым для pending задач или при создании.
	}

	taskRows := sqlmock.NewRows([]string{"id", "expression_id", "operation", "arg1", "arg2", "status", "result", "error_message", "created_at", "updated_at"}). // Список колонок
																					AddRow(
			task1.ID, task1.ExpressionID, task1.Operation, task1.Arg1, task1.Arg2,
			task1.Status, task1.Result, task1.ErrorMessage, task1.CreatedAt, task1.UpdatedAt,
		). // Добавляем строку task1
		AddRow(
			task2.ID, task2.ExpressionID, task2.Operation, task2.Arg1, task2.Arg2,
			task2.Status, task2.Result, task2.ErrorMessage, task2.CreatedAt, task2.UpdatedAt,
		) // Добавляем строку task2

	// Имитируем ожидаемый SQL SELECT запрос для ЗАДАЧ.
	// Убедись, что этот паттерн ТОЧНО соответствует запросу selectTasksSQL в GetExpressionHandler.
	selectTasksSQLPattern := `^\s*SELECT\s+id,\s*expression_id,\s*operation,\s+arg1,\s+arg2,\s+status,\s+result,\s*error_message,\s+created_at,\s+updated_at\s+FROM\s+tasks\s+WHERE\s+expression_id\s*=\s*\?\s*$`

	// Настраиваем ВТОРОЕ ожидание мока БД: ожидаем запрос задач.
	mock.ExpectQuery(selectTasksSQLPattern). // Ожидаем запрос, соответствующий регулярке задач
							WithArgs(requestedExpressionID). // Ожидаем, что запрос будет с аргументом ID выражения
							WillReturnRows(taskRows)         // Мок вернет подготовленные нами строки задач

	// 5. Выполнение: Создаем HTTP запрос и отправляем его тестовому серверу.
	// Этот раздел создает сам запрос и выполняет его, объявляя переменные resp, err, bodyBytes.
	// Создаем запрос к АДРЕСУ тестового сервера с нужным путем и ID.
	reqURL := testServer.URL + "/expressions/" + requestedExpressionID
	req, err := http.NewRequest("GET", reqURL, nil) // <-- объявляется err
	assert.NoError(t, err, "Создание HTTP запроса не должно возвращать ошибку")

	// Отправляем созданный запрос тестовому серверу.
	resp, err := http.DefaultClient.Do(req) // <-- объявляются resp и новый err
	assert.NoError(t, err, "Отправка запроса тестовому серверу не должна возвращать ошибку")
	defer resp.Body.Close() // Важно закрыть тело ответа после его использования

	// Читаем все тело ответа.
	bodyBytes, err := io.ReadAll(resp.Body) // <-- объявляются bodyBytes и новый err
	assert.NoError(t, err, "Чтение тела ответа не должно возвращать ошибку")

	// 6. Проверки: Проверяем статус код ответа и его тело.
	// Переменные resp, err, bodyBytes используются здесь, так как они были объявлены выше в разделе 5.
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Статус код должен быть 200 OK при успешном получении выражения")

	var actualResponse localModels.ExpressionDetailsResponse
	err = json.Unmarshal(bodyBytes, &actualResponse)
	assert.NoError(t, err, "Тело ответа должно быть валидным JSON объектом ExpressionDetailsResponse")

	// Проверяем, что возвращенное ВЫРАЖЕНИЕ в ответе соответствует ожидаемому.
	// Сравниваем ключевые поля выражения.
	assert.Equal(t, expectedExpression.ID, actualResponse.Expression.ID, "ID возвращенного выражения должен совпадать с запрошенным")                     // <-- Используем actualResponse.Expression.ID
	assert.Equal(t, expectedExpression.UserID, actualResponse.Expression.UserID, "UserID возвращенного выражения должен совпадать с UserID из контекста") // <-- Используем actualResponse.Expression.UserID

	// Проверяем другие поля ВЫРАЖЕНИЯ.
	assert.Equal(t, expectedExpression.ExpressionString, actualResponse.Expression.ExpressionString, "Строка выражения должна совпадать")
	assert.Equal(t, expectedExpression.Status, actualResponse.Expression.Status, "Статус выражения должен совпадать")

	// Проверяем nullable поля ВЫРАЖЕНИЯ FinalResult и ErrorMessage.
	assert.Equal(t, expectedExpression.FinalResult.Valid, actualResponse.Expression.FinalResult.Valid, "Флаг Valid для FinalResult должен совпадать")
	if expectedExpression.FinalResult.Valid {
		assert.Equal(t, expectedExpression.FinalResult.Float64, actualResponse.Expression.FinalResult.Float64, "Значение FinalResult должно совпадать")
	}
	assert.Equal(t, expectedExpression.ErrorMessage.Valid, actualResponse.Expression.ErrorMessage.Valid, "Флаг Valid для ErrorMessage должен совпадать")
	if expectedExpression.ErrorMessage.Valid {
		assert.Equal(t, expectedExpression.ErrorMessage.String, actualResponse.Expression.ErrorMessage.String, "Значение ErrorMessage должно совпадать")
	}
	// Проверяем поля времени ВЫРАЖЕНИЯ.
	assert.False(t, actualResponse.Expression.CreatedAt.IsZero(), "CreatedAt выражения не должно быть нулевым значением")
	assert.False(t, actualResponse.Expression.UpdatedAt.IsZero(), "UpdatedAt выражения не должно быть нулевым значением")

	// Проверяем, что список ЗАДАЧ в ответе соответствует ожидаемому.
	assert.Len(t, actualResponse.Tasks, 2, "В ответе должно быть 2 задачи") // Проверяем количество задач

	// Проверяем содержимое задач. Можно сравнить по ID.
	// Порядок задач в ответе будет соответствовать порядку добавления в taskRows мока.
	assert.Equal(t, task1.ID, actualResponse.Tasks[0].ID, "ID первой задачи в ответе должно совпадать")
	assert.Equal(t, task2.ID, actualResponse.Tasks[1].ID, "ID второй задачи в ответе должно совпадать")
	// Можно добавить более детальные проверки полей задач, если нужно.

	// Проверяем, что все ожидания мока БД были выполнены (т.е. оба SELECT были вызваны обработчиком и соответствовали ExpectQuery).
	err = mock.ExpectationsWereMet() // <-- используется err
	assert.NoError(t, err, "Все ожидания мока базы данных должны быть выполнены")
}

// TestGetExpressionHandler_InvalidUUID: Тест получения деталей выражения с невалидным ID в URL.
func TestGetExpressionHandler_InvalidUUID(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных и экземпляр сервиса.
	db, mock := setupTestDB(t)
	defer db.Close() // Закрываем соединение с моком после завершения теста

	// Создаем экземпляр нашего сервиса API.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя (нужен для тестового middleware).
	testUserID := int64(301) // Произвольный тестовый ID пользователя

	// 2. Имитируем работу роутера и AuthMiddleware.
	router := mux.NewRouter()
	// Наш GetExpressionHandler (теперь он валидирует UUID в начале)
	getExpressionHandler := http.HandlerFunc(apiService.GetExpressionHandler)
	// Тестовый middleware для добавления UserID в контекст.
	handlerWithAuth := testAuthMiddleware(testUserID, getExpressionHandler)

	// Регистрируем обработчик с middleware на пути с переменной {id}.
	router.Handle("/expressions/{id}", handlerWithAuth).Methods("GET")

	// Создаем тестовый HTTP сервер, который будет использовать наш роутер.
	testServer := httptest.NewServer(router)
	defer testServer.Close() // Закрываем тестовый сервер после завершения теста

	// 3. Выполнение: Создаем HTTP запрос с НЕВАЛИДНЫМ UUID в URL и отправляем его тестовому серверу.
	invalidExpressionID := "this-is-not-a-valid-uuid-format" // Заведомо НЕВАЛИДНЫЙ UUID

	// Создаем запрос к АДРЕСУ тестового сервера с невалидным ID в пути.
	reqURL := testServer.URL + "/expressions/" + invalidExpressionID
	req, err := http.NewRequest("GET", reqURL, nil)
	assert.NoError(t, err, "Создание HTTP запроса не должно возвращать ошибку")

	// UserID будет добавлен в контекст тестовым middleware,
	// но handler должен выйти раньше из-за невалидного UUID в URL.
	// Мы все равно проходим через middleware в тесте.

	// Отправляем созданный запрос тестовому серверу.
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err, "Отправка запроса тестовому серверу не должна возвращать ошибку")
	defer resp.Body.Close() // Закрываем тело ответа

	// 4. Проверки: Проверяем статус код ответа.
	// Ожидаем 400 Bad Request, потому что ID в URL не является валидным UUID.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Статус код должен быть 400 Bad Request для невалидного UUID")

	err = mock.ExpectationsWereMet() // Проверяет, что все EXPECT-ожидания были выполнены И не было НЕОЖИДАННЫХ вызовов.
	assert.NoError(t, err, "Не должно быть вызовов к моку базы данных в этом сценарии")

}

// TestGetExpressionHandler_DatabaseError: Тест получения деталей выражения при возникновении ошибки базы данных (500 Internal Server Error).
// В этом сценарии база данных имитирует общую ошибку при выполнении запроса выборки выражения.
func TestGetExpressionHandler_DatabaseError(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных и экземпляр сервиса.
	db, mock := setupTestDB(t)
	defer db.Close() // Закрываем соединение с моком после завершения теста

	// Создаем экземпляр нашего сервиса API.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// ID пользователя.
	testUserID := int64(301) // Произвольный тестовый ID пользователя

	// ID выражения (валидный UUID, запрос для него будет выполнен).
	requestedExpressionID := uuid.New().String() // Используем валидный UUID для запроса

	// 2. Имитируем работу роутера и AuthMiddleware.
	router := mux.NewRouter()
	// Получаем наш GetExpressionHandler.
	getExpressionHandler := http.HandlerFunc(apiService.GetExpressionHandler)
	// Оборачиваем его в тестовый AuthMiddleware, который добавит UserID.
	handlerWithAuth := testAuthMiddleware(testUserID, getExpressionHandler)

	// Регистрируем обработчик с middleware на пути с переменной {id}.
	router.Handle("/expressions/{id}", handlerWithAuth).Methods("GET")

	// Создаем тестовый HTTP сервер, который будет использовать наш роутер.
	testServer := httptest.NewServer(router)
	defer testServer.Close() // Закрываем тестовый сервер после завершения теста

	// 3. Настройка мока БД: Имитируем общую ошибку при выборке выражения.
	// Ожидаем ТОЛЬКО первый SQL SELECT запрос (выборка выражения из таблицы expressions).
	// Этот запрос должен ВЕРНУТЬ ПРОИЗВОЛЬНУЮ ОШИБКУ (отличную от sql.ErrNoRows).

	// Паттерн SQL запроса для выборки выражения (должен точно соответствовать запросу в GetExpressionHandler).
	selectExpressionSQLPattern := `^\s*SELECT\s+id,\s*user_id,\s*expression_string,\s+status,\s+result,\s*error_message,\s+created_at,\s*updated_at\s+FROM\s+expressions\s+WHERE\s+id\s*=\s*\?\s+AND\s+user_id\s*=\s*\?\s*$`

	// Создаем имитированную ошибку базы данных.
	dbError := errors.New("simulated database query error for GetExpressionHandler")

	// Настраиваем ожидание мока: ожидаем запрос выражения с нужными аргументами.
	mock.ExpectQuery(selectExpressionSQLPattern). // Ожидаем запрос, соответствующий паттерну
							WithArgs(requestedExpressionID, testUserID). // Ожидаем, что аргументы будут ID выражения и UserID из контекста
							WillReturnError(dbError)

	// 4. Выполнение: Создаем HTTP запрос с валидным ID и отправляем его.
	reqURL := testServer.URL + "/expressions/" + requestedExpressionID
	req, err := http.NewRequest("GET", reqURL, nil)
	assert.NoError(t, err, "Создание HTTP запроса не должно возвращать ошибку")

	// Отправляем созданный запрос тестовому серверу.
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err, "Отправка запроса тестовому серверу не должна возвращать ошибку")
	defer resp.Body.Close() // Закрываем тело ответа

	// 5. Проверки: Проверяем статус код ответа.
	// Ожидаем 500 Internal Server Error, потому что произошла ошибка базы данных.
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "Статус код должен быть 500 Internal Server Error при ошибке базы данных")

	// Проверяем, что все ожидания мока БД были выполнены.
	// В этом тесте мы настроили только одно ожидание (для первого SELECT) и оно должно было сработать и вернуть ошибку.
	// Проверяем, что не было других (неожиданных) вызовов к БД.
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Все ожидания мока базы данных должны быть выполнены (только 1 запрос SELECT expressions, вернувший ошибку)")
}

// TestGetExpressionHandler_UserIDMissingFromContext: Тест получения деталей выражения, когда UserID отсутствует в контексте запроса (401 Unauthorized).
// Это проверяет корректную работу логики авторизации (или ее отсутствия) перед доступом к ресурсу.
func TestGetExpressionHandler_UserIDMissingFromContext(t *testing.T) {
	// 1. Подготовка: Создаем мок базы данных и экземпляр сервиса.
	db, mock := setupTestDB(t)
	defer db.Close() // Закрываем соединение с моком после завершения теста

	// Создаем экземпляр нашего сервиса API.
	jwtSecret := []byte("test_secret_key")
	apiService := NewAPIService(db, jwtSecret)

	// 2. Имитируем работу роутера, но БЕЗ middleware, ДОБАВЛЯЮЩЕГО UserID в контекст.
	// Это имитирует ситуацию, когда запрос пришел без валидного JWT или другой авторизационной информации.
	router := mux.NewRouter()

	// Получаем наш GetExpressionHandler как http.HandlerFunc.
	getExpressionHandler := http.HandlerFunc(apiService.GetExpressionHandler)

	// Это имитирует прохождение запроса без установки UserID в контекст.
	router.Handle("/expressions/{id}", getExpressionHandler).Methods("GET")

	// Создаем тестовый HTTP сервер, который будет использовать наш настроенный тестовый роутер.
	testServer := httptest.NewServer(router)
	defer testServer.Close() // Важно закрыть тестовый сервер после завершения теста

	// 3. Выполнение: Создаем HTTP запрос с валидным ID выражения и отправляем его.
	// В контексте этого запроса НЕ БУДЕТ UserID.
	validExpressionID := uuid.New().String() // Используем валидный UUID для URL

	// Создаем запрос к АДРЕСУ тестового сервера с валидным ID в пути.
	reqURL := testServer.URL + "/expressions/" + validExpressionID
	req, err := http.NewRequest("GET", reqURL, nil)
	assert.NoError(t, err, "Создание HTTP запроса не должно возвращать ошибку")

	// Отправляем созданный запрос тестовому серверу.
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err, "Отправка запроса тестовому серверу не должна возвращать ошибку")
	defer resp.Body.Close() // Важно закрыть тело ответа после его использования

	// 4. Проверки: Проверяем статус код ответа.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Статус код должен быть 401 Unauthorized, когда UserID отсутствует в контексте")

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err, "Не должно быть вызовов к моку базы данных в этом сценарии")
}
