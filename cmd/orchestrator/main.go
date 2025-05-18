package main

import (
	"context"
	//"database/sql"
	//"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	_ "modernc.org/sqlite"

	localAuth "calculator_project/internal/auth"
	localConfig "calculator_project/internal/config"
	localDB "calculator_project/internal/orchestrator/db"
	generatedGrpc "calculator_project/internal/orchestrator/grpc"
	serverImpl "calculator_project/internal/orchestrator/grpcserver"
	localHandlers "calculator_project/internal/orchestrator/handlers"
	"google.golang.org/grpc"
)

func main() {
	// 1. Загрузка конфигурации.
	log.Println("Запуск сервиса Оркестратора...")
	cfg, err := localConfig.LoadConfig() // Загружаем конфигурацию
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err) // Если конфигурация не загружена, останавливаемся
	}
	log.Printf("Конфигурация успешно загружена: %+v", cfg)

	// 2. Инициализация базы данных SQLite.
	// Открываем соединение с базой данных SQLite.
	// Используем fmt.Sprintf для создания строки соединения.
	db, err := localDB.InitDB(cfg.DatabaseFile)
	if err != nil {
		log.Fatalf("Ошибка открытия базы данных '%s': %v", cfg.DatabaseFile, err)
	}
	defer db.Close() // Гарантируем закрытие соединения при завершении main

	// Проверяем соединение с базой данных.
	if err = db.Ping(); err != nil {
		log.Fatalf("Ошибка подключения к базе данных '%s': %v", cfg.DatabaseFile, err)
	}
	log.Printf("Database '%s' initialized successfully.", cfg.DatabaseFile)

	log.Println("База данных инициализирована успешно.") // Этот лог может быть после инициализации или после миграций

	// 4. Создание экземпляров сервисов (HTTP API и gRPC).
	// Передаем соединение с базой данных и другие зависимости.
	// localHandlers.NewAPIService принимает DB и JWTSecret []byte.
	apiService := localHandlers.NewAPIService(db, []byte(cfg.JWTSecret))

	// localGRPC.NewGRPCServer принимает DB и Config.
	grpcServerInstance := serverImpl.NewGRPCServer(db, cfg) // Создаем экземпляр gRPC сервера

	// 5. Настройка и запуск gRPC-сервера в отдельной горутине.
	log.Printf("Запуск gRPC-сервера на %s...", cfg.GRPCListenAddr)
	// Создаем слушатель для gRPC.
	lis, err := net.Listen("tcp", cfg.GRPCListenAddr)
	if err != nil {
		log.Fatalf("Ошибка при создании слушателя для gRPC: %v", err)
	}

	// Создаем сам gRPC сервер.
	grpcServer := grpc.NewServer()
	// Регистрируем наш сервис (CalculatorService) на gRPC сервере.
	// Метод RegisterCalculatorServiceServer генерируется protoc.
	generatedGrpc.RegisterCalculatorServiceServer(grpcServer, grpcServerInstance)

	// Запускаем gRPC сервер в отдельной горутине, чтобы не блокировать main.
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Ошибка запуска gRPC-сервера: %v", err) // Если сервер не смог запуститься
		}
	}()

	// 6. Настройка и запуск HTTP-сервера в отдельной горутине.
	log.Printf("Запуск HTTP-сервера на %s...", cfg.HTTPListenAddr)
	// Создаем маршрутизатор HTTP (gorilla/mux).
	router := mux.NewRouter()

	// Создаем подмаршрутизатор для API v1
	apiV1 := router.PathPrefix("/api/v1").Subrouter()

	// Применяем middleware аутентификации ко всем маршрутам apiV1.
	// Убедись, что localAuth.AuthMiddleware принимает []byte для JWTSecret.
	apiV1.Use(localAuth.AuthMiddleware([]byte(cfg.JWTSecret)))

	// Маршруты, защищенные аутентификацией.
	apiV1.HandleFunc("/calculate", apiService.CalculateHandler).Methods("POST")
	apiV1.HandleFunc("/expressions", apiService.ListExpressionsHandler).Methods("GET")
	// Маршрут для получения деталей одного выражения по ID (защищен).
	// `{id}` - это переменная пути, которая будет доступна через mux.Vars(r).
	apiV1.HandleFunc("/expressions/{id}", apiService.GetExpressionHandler).Methods("GET")

	// Маршруты, не требующие аутентификации (регистрируются ДО применения middleware apiV1).
	router.HandleFunc("/api/v1/register", apiService.RegisterHandler).Methods("POST")
	router.HandleFunc("/api/v1/login", apiService.LoginHandler).Methods("POST")

	// Создаем экземпляр HTTP сервера.
	httpServer := &http.Server{
		Addr:         cfg.HTTPListenAddr,
		Handler:      router, // Используем наш маршрутизатор
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Запускаем HTTP сервер в отдельной горутине.
	go func() {
		// ListenAndServe блокирует выполнение, поэтому запускаем в горутине.
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска HTTP-сервера: %v", err) // Если сервер не смог запуститься (кроме штатного завершения)
		}
	}()

	// 7. Ожидание сигнала завершения и реализация graceful shutdown.
	log.Println("Оркестратор запущен и ожидает сигнала завершения (Ctrl+C, SIGTERM, SIGQUIT)...")

	// Создаем канал для получения сигналов ОС.
	quit := make(chan os.Signal, 1)
	// Регистрируем сигналы, которые мы хотим перехватывать.
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT) // Ctrl+C, kill, kill -s QUIT

	// Блокируем выполнение до получения сигнала.
	<-quit
	log.Println("Получен сигнал завершения, начало процедуры graceful shutdown...")

	// Запускаем процедуру плавного завершения HTTP-сервера.
	log.Println("Остановка HTTP сервера...")
	// Создаем контекст с таймаутом для graceful shutdown.
	ctxHTTP, cancelHTTP := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHTTP() // Освобождаем ресурсы контекста

	// Вызываем Shutdown для HTTP сервера.
	if err := httpServer.Shutdown(ctxHTTP); err != nil {
		log.Printf("Ошибка при плавном завершении HTTP сервера: %v", err)
	} else {
		log.Println("HTTP server плавно остановлен.")
	}

	// Запускаем процедуру плавного завершения gRPC-сервера.
	log.Println("Остановка gRPC сервера...")
	// GracefulStop позволяет gRPC серверу дождаться завершения текущих запросов.
	grpcServer.GracefulStop()
	log.Println("gRPC server плавно остановлен.")

	log.Println("Сервис Оркестратора остановлен.")
}
