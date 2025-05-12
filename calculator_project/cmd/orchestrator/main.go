package main

import (
	// "database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	// "calculator_project/internal/auth"
	"calculator_project/internal/orchestrator"
	"calculator_project/internal/orchestrator/handlers"

	"github.com/gorilla/mux"
)

// Config: Структура для хранения конфигурации сервиса Оркестратора.
type Config struct {
	DatabaseFile string

	TimeAdditionMs       time.Duration
	TimeSubtractionMs    time.Duration
	TimeMultiplicationMs time.Duration
	TimeDivisionMs       time.Duration

	HTTPListenAddr string
	gRPCListenAddr string

	JWTSecret string
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

	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("переменная среды JWT_SECRET не установлена или пуста")
	}

	return cfg, nil
}

func main() {
	log.Println("Запуск сервиса Оркестратора...")

	// Загрузка конфигурации.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}
	log.Printf("Конфигурация успешно загружена: %+v", cfg)

	// Инициализация базы данных.
	db, err := orchestrator.InitDB()
	if err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}
	defer db.Close()

	log.Println("База данных инициализирована успешно.")

	// *** Настройка HTTP-сервера ***

	router := mux.NewRouter()

	apiService := handlers.NewAPIService(db, cfg.JWTSecret)

	apiV1 := router.PathPrefix("/api/v1").Subrouter()

	apiV1.HandleFunc("/register", apiService.RegisterHandler).Methods("POST")

	apiV1.HandleFunc("/login", apiService.LoginHandler).Methods("POST")

	apiV1.HandleFunc("/calculate", apiService.CalculateHandler).Methods("POST")
	apiV1.HandleFunc("/expressions", apiService.ListExpressionsHandler).Methods("GET")
	apiV1.HandleFunc("/expressions/{id}", apiService.GetExpressionHandler).Methods("GET")

	log.Printf("Запуск HTTP-сервера на %s...", cfg.HTTPListenAddr)
	err = http.ListenAndServe(cfg.HTTPListenAddr, router)
	if err != nil {
		log.Fatalf("Ошибка запуска HTTP-сервера: %v", err)
	}
}
