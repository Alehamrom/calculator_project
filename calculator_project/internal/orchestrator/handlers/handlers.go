package handlers // Объявляем пакет handlers

import (
	"database/sql"  // Для работы с базой данных
	"encoding/json" // Для работы с JSON (декодирование запроса)
	// "fmt"           // Для форматирования ошибок
	"log"      // Для логирования
	"net/http" // Для работы с HTTP (ResponseWriter, Request, status codes)
	"strings"  // Для проверки строк (в isUniqueConstraintError)

	// Локальные импорты из других внутренних пакетов проекта.
	// Используем алиасы, чтобы избежать конфликтов имен (особенно с net/http).
	localAuth "calculator_project/internal/auth" // Импортируем пакет auth
	localHTTP "calculator_project/internal/http" // Импортируем наши HTTP утилиты
	// Need to import the Config struct definition from main? No, better to define it in a shared place like internal/config.
	// Or pass only necessary parts of config to APIService. Passing the whole *main.Config is okay for now if we accept the dependency on the main package's struct.
	// Let's define a minimal config struct needed by handlers within this package, or pass specific values from main.
	// Passing the whole *main.Config is simplest initially, but creates a dependency cycle if handlers need to import main.
	// A better pattern is a shared config struct in internal/config or passing primitive config values.
	// Let's pass the relevant config values (like operation times, maybe JWT secrets) directly to NewAPIService or store them in APIService struct.
	// For now, the handlers don't need config (except maybe JWT secret later), let's skip Config in APIService initially.
	// The DB is the primary dependency for persistence and users.
)

// RegisterRequest представляет структуру тела запроса для регистрации пользователя.
type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// APIService: Структура, которая будет содержать зависимости, необходимые обработчикам.
// Например, соединение с базой данных.
type APIService struct {
	DB *sql.DB // Соединение с базой данных SQLite
	// Здесь можно будет добавить другие зависимости, например, сервис для JWT, менеджер задач и т.д.
}

// NewAPIService: Функция-конструктор для создания нового экземпляра APIService.
// Принимает необходимые зависимости (например, *sql.DB) и возвращает указатель на APIService.
func NewAPIService(db *sql.DB) *APIService {
	return &APIService{DB: db}
}

// RegisterHandler: Обработчик HTTP-запросов на регистрацию пользователя (POST /api/v1/register).
// Это метод структуры APIService, что дает ему доступ к полям APIService (например, к DB).
func (s *APIService) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получен запрос на регистрацию пользователя")

	// Убедимся, что тело запроса будет закрыто после прочтения.
	defer r.Body.Close()

	// 1. Парсим (декодируем) тело запроса из JSON в нашу структуру RegisterRequest.
	var req RegisterRequest
	// json.NewDecoder читает из io.Reader (r.Body) и декодирует в структуру.
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		// Если тело запроса не является валидным JSON или не соответствует структуре RegisterRequest,
		// возвращаем ошибку 400 Bad Request с сообщением.
		log.Printf("Ошибка при декодировании тела запроса регистрации: %v", err)
		localHTTP.RespondError(w, http.StatusBadRequest, "Invalid request body format") // Используем нашу утилиту RespondError
		return                                                                          // Завершаем выполнение обработчика
	}

	// 2. Базовая валидация входных данных (проверяем, что логин и пароль не пустые).
	if req.Login == "" || req.Password == "" {
		log.Println("Запрос на регистрацию с пустым логином или паролем.")
		localHTTP.RespondError(w, http.StatusBadRequest, "Login and password cannot be empty")
		return
	}

	// TODO: Здесь можно добавить более сложные проверки валидности логина/пароля (минимальная длина, допустимые символы и т.д.).

	// 3. Хешируем пароль перед сохранением в базу данных.
	hashedPassword, err := localAuth.HashPassword(req.Password) // Используем функцию из нашего пакета auth
	if err != nil {
		// Если хеширование не удалось (крайне редкая внутренняя ошибка), возвращаем 500.
		log.Printf("Ошибка при хешировании пароля для пользователя '%s': %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// 4. Сохраняем нового пользователя в базу данных.
	// Подготовленный SQL-запрос для вставки данных. "?" - плейсхолдеры для значений.
	insertUserSQL := `INSERT INTO users (login, password_hash) VALUES (?, ?)`
	// Выполняем SQL-запрос на вставку, передавая логин и хешированный пароль в качестве аргументов.
	// s.DB - это соединение с базой данных, доступное через структуру APIService.
	_, err = s.DB.Exec(insertUserSQL, req.Login, hashedPassword)

	if err != nil {
		// 5. Обрабатываем ошибки при работе с базой данных.
		// Проверяем, является ли ошибка нарушением уникального ограничения (логин уже существует).
		if isUniqueConstraintError(err) { // Используем нашу вспомогательную функцию
			log.Printf("Ошибка регистрации: Логин '%s' уже существует.", req.Login)
			// Возвращаем статус 409 Conflict, если логин уже занят.
			localHTTP.RespondError(w, http.StatusConflict, "Login already exists")
			return
		}
		// Для любых других ошибок базы данных (например, проблема с соединением), возвращаем 500.
		log.Printf("Ошибка при вставке пользователя '%s' в базу данных: %v", req.Login, err)
		localHTTP.RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// 6. Если все прошло успешно, отправляем ответ 200 OK.
	log.Printf("Пользователь '%s' успешно зарегистрирован.", req.Login)
	// Условие проекта требует "200+OK". Отправим пустой JSON объект {}.
	localHTTP.RespondJSON(w, http.StatusOK, map[string]string{}) // Или можно было бы RespondJSON(w, http.StatusOK, nil), но пустой объект {"name":{}} может быть понятнее. Требование было {"name":"введенное_пользователем_имя"} для HelloHandler, для регистрации { } или пустота, судя по "200+OK". Отправим {}.
}

// isUniqueConstraintError: Вспомогательная функция для проверки, является ли ошибка базы данных
// ошибкой нарушения уникального ограничения (например, дублирование логина).
// Реализация может зависеть от используемого драйвера СУБД.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false // Нет ошибки - не нарушение ограничения
	}
	// Для драйвера github.com/mattn/go-sqlite3, ошибки нарушения уникального ограничения
	// часто содержат в тексте "UNIQUE constraint failed".
	// Это простой, но рабочий способ проверки для SQLite.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// --- Заглушки для других обработчиков API ---
// Добавляем пустые методы для других эндпоинтов /api/v1/, чтобы их можно было использовать в main.go
// Эти методы будут реализованы позже.

func (s *APIService) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация входа пользователя и выдачи JWT
	log.Println("Вызван LoginHandler (TODO)")
	w.Write([]byte("Login endpoint (TODO)"))
}

func (s *APIService) CalculateHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация приема выражения, парсинга, создания задач, сохранения в БД
	log.Println("Вызван CalculateHandler (TODO)")
	w.Write([]byte("Calculate endpoint (TODO)"))
}

func (s *APIService) ListExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация получения списка выражений из БД для текущего пользователя
	log.Println("Вызван ListExpressionsHandler (TODO)")
	w.Write([]byte("List Expressions endpoint (TODO)"))
}

func (s *APIService) GetExpressionHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация получения выражения по ID из БД для текущего пользователя (с учетом пользователя)
	log.Println("Вызван GetExpressionHandler (TODO)")
	// Пример получения переменной из пути (id)
	// vars := mux.Vars(r) // Нужен импорт "github.com/gorilla/mux" в этом файле, если использовать здесь
	// expressionID := vars["id"]
	w.Write([]byte("Get Expression endpoint (TODO)"))
}
