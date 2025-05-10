package main

import (
	// "database/sql"
	"fmt"
	"log"
	"net/http" // Импортируем пакет http для работы с HTTP-сервером
	"os"
	"strconv"
	"time"

	"calculator_project/internal/orchestrator"
	// Сюда позже добавим импорт для bcrypt и auth
	"github.com/gorilla/mux" // Импортируем маршрутизатор gorilla/mux
)

type Config struct {
	DatabaseFile string

	TimeAdditionMs       time.Duration
	TimeSubtractionMs    time.Duration
	TimeMultiplicationMs time.Duration
	TimeDivisionMs       time.Duration

	HTTPListenAddr string
	gRPCListenAddr string
}

// getEnvDuration: Вспомогательная функция для чтения переменной среды и преобразования в time.Duration.
func getEnvDuration(key string, defaultVal time.Duration) (time.Duration, error) {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal, nil
	}
	valInt, err := strconv.Atoi(valStr)
	if err != nil {
		return 0, fmt.Errorf("переменная среды %s имеет неверный формат числа: %w", key, err)
	}
	return time.Duration(valInt) * time.Millisecond, nil
}

// loadConfig: Читает конфигурацию из переменных среды.
func loadConfig() (*Config, error) {
	cfg := &Config{
		DatabaseFile:   "calculator.db",
		HTTPListenAddr: ":8080",
		gRPCListenAddr: ":50051",
	}

	var err error
	cfg.TimeAdditionMs, err = getEnvDuration("TIME_ADDITION_MS", 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	cfg.TimeSubtractionMs, err = getEnvDuration("TIME_SUBTRACTION_MS", 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	cfg.TimeMultiplicationMs, err = getEnvDuration("TIME_MULTIPLICATIONS_MS", 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	cfg.TimeDivisionMs, err = getEnvDuration("TIME_DIVISIONS_MS", 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	if httpAddr := os.Getenv("HTTP_LISTEN_ADDR"); httpAddr != "" {
		cfg.HTTPListenAddr = httpAddr
	}
	if grpcAddr := os.Getenv("GRPC_LISTEN_ADDR"); grpcAddr != "" {
		cfg.gRPCListenAddr = grpcAddr
	}

	return cfg, nil
}

// getEnvDuration: Вспомогательная функция для чтения переменной среды,
// преобразования ее в time.Duration (считая, что значение в миллисекундах)
// и предоставления значения по умолчанию, если переменная не установлена или не парсится как число.

func main() {
	log.Println("Запуск сервиса Оркестратора...")

	// Загрузка конфигурации.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}
	log.Printf("Конфигурация успешно загружена: %+v", cfg)

	// Инициализация базы данных.
	db, err := orchestrator.InitDB() // Используем исправленный путь импорта
	if err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}
	defer db.Close() // Закрытие соединения с БД при выходе из main

	log.Println("База данных инициализирована успешно.")

	// *** Настройка HTTP-сервера ***

	// 1. Создаем новый маршрутизатор Gorilla Mux.
	router := mux.NewRouter()

	// TODO: Здесь можно добавить middleware, например, для логирования или аутентификации

	// 2. Определяем маршруты и привязываем к ним функции-обработчики.
	// Публичное API находится по пути /api/v1.
	apiV1 := router.PathPrefix("/api/v1").Subrouter() // Создаем подмаршрутизатор для /api/v1

	// Маршрут для регистрации пользователя (POST /api/v1/register).
	apiV1.HandleFunc("/register", RegisterHandler).Methods("POST")

	// Маршрут для входа пользователя (POST /api/v1/login).
	apiV1.HandleFunc("/login", LoginHandler).Methods("POST")

	// Маршрут для добавления вычисления выражения (POST /api/v1/calculate).
	apiV1.HandleFunc("/calculate", CalculateHandler).Methods("POST")

	// Маршрут для получения списка выражений (GET /api/v1/expressions).
	apiV1.HandleFunc("/expressions", ListExpressionsHandler).Methods("GET")

	// Маршрут для получения выражения по его идентификатору (GET /api/v1/expressions/:id).
	// ":id" - это переменная часть пути, mux будет парсить её.
	apiV1.HandleFunc("/expressions/{id}", GetExpressionHandler).Methods("GET")

	// TODO: Здесь будем привязывать db и cfg к нашим обработчикам,
	// например, передавая их в функции-конструкторы обработчиков или используя замыкания.

	// 3. Запускаем HTTP-сервер.
	log.Printf("Запуск HTTP-сервера на %s...", cfg.HTTPListenAddr)
	// http.ListenAndServe блокирует выполнение main до остановки сервера.
	err = http.ListenAndServe(cfg.HTTPListenAddr, router) // Передаем наш маршрутизатор
	if err != nil {
		// Если сервер не смог запуститься или остановился с ошибкой, выводим фатальную ошибку.
		log.Fatalf("Ошибка запуска HTTP-сервера: %v", err)
	}

	// TODO: Запуск gRPC сервера для Агентов будет добавлен позже.
}

// *** Заглушки функций-обработчиков публичного API ***
// Эти функции будут реализованы позже, сейчас они просто нужны, чтобы код компилировался.

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация регистрации пользователя
	log.Println("Вызван RegisterHandler")
	w.Write([]byte("Register endpoint (TODO)")) // Временный ответ
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация входа пользователя и выдачи JWT
	log.Println("Вызван LoginHandler")
	w.Write([]byte("Login endpoint (TODO)")) // Временный ответ
}

func CalculateHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация приема выражения, парсинга, создания задач, сохранения в БД
	log.Println("Вызван CalculateHandler")
	w.Write([]byte("Calculate endpoint (TODO)")) // Временный ответ
}

func ListExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация получения списка выражений из БД для текущего пользователя
	log.Println("Вызван ListExpressionsHandler")
	w.Write([]byte("List Expressions endpoint (TODO)")) // Временный ответ
}

func GetExpressionHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Реализация получения выражения по ID из БД для текущего пользователя
	log.Println("Вызван GetExpressionHandler")
	// Пример получения переменной из пути (id)
	// vars := mux.Vars(r)
	// expressionID := vars["id"]
	w.Write([]byte("Get Expression endpoint (TODO)")) // Временный ответ
}

// main функция не нужна для отправки в LMS.
