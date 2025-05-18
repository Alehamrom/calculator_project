package config

import (
	"fmt"
	"log"
	// "os"
	// "strconv"
	"time"

	"github.com/spf13/viper"
)

// Config: Структура для хранения конфигурации сервиса Оркестратора.
// Читается из переменных среды.
type Config struct {
	DatabaseFile         string        `mapstructure:"DATABASE_FILE"`
	TimeAdditionMs       time.Duration `mapstructure:"TIME_ADDITION_MS"`
	TimeSubtractionMs    time.Duration `mapstructure:"TIME_SUBTRACTION_MS"`
	TimeMultiplicationMs time.Duration `mapstructure:"TIME_MULTIPLICATION_MS"`
	TimeDivisionMs       time.Duration `mapstructure:"TIME_DIVISION_MS"`
	HTTPListenAddr       string        `mapstructure:"HTTP_LISTEN_ADDR"` // <--- Должно быть экспортировано
	GRPCListenAddr       string        `mapstructure:"GRPC_LISTEN_ADDR"` // <--- Должно быть экспортировано
	JWTSecret            []byte        `mapstructure:"JWT_SECRET"`       // <--- Должно быть экспортировано
}

func LoadConfig() (*Config, error) {
	// Настраиваем Viper
	viper.AddConfigPath(".")    // Искать файл конфигурации в текущей директории (.)
	viper.SetConfigName(".env") // Имя файла конфигурации (без расширения, если тип auto)
	viper.SetConfigType("env")  // Тип файла конфигурации - .env

	// Читать переменные окружения. Переменные окружения имеют приоритет.
	viper.AutomaticEnv()

	// Попытаться прочитать файл конфигурации. Если файл не найден, это не ошибка.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Если ошибка не "файл не найден", то это реальная проблема.
			log.Printf("Ошибка чтения файла конфигурации: %v", err)
			// Можно продолжить попытку чтения из переменных окружения, но лучше залогировать.
		}
	}

	// Устанавливаем значения по умолчанию для некоторых параметров, если они не найдены
	// в файле или переменных окружения.
	viper.SetDefault("DATABASE_FILE", "calculator.db")
	viper.SetDefault("HTTP_LISTEN_ADDR", ":8080")
	viper.SetDefault("GRPC_LISTEN_ADDR", ":50051")

	// Время операций в .env или переменных окружения должно быть в формате time.Duration (напр. "100ms")
	// Или можно читать как int и преобразовывать, но формат time.Duration предпочтительнее для Viper.
	// Установим значения по умолчанию в time.Duration, если они не заданы явно.
	viper.SetDefault("TIME_ADDITION_MS", "100ms")
	viper.SetDefault("TIME_SUBTRACTION_MS", "100ms")
	viper.SetDefault("TIME_MULTIPLICATION_MS", "100ms")
	viper.SetDefault("TIME_DIVISION_MS", "100ms")

	cfg := &Config{}

	// Распаковываем прочитанные значения в структуру Config
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("невозможно распаковать конфигурацию: %w", err)
	}

	// JWT_SECRET - проверяем его отдельно, так как он обязателен
	// Viper читает его как строку, затем мы преобразуем в []byte
	jwtSecretString := viper.GetString("JWT_SECRET")
	if jwtSecretString == "" {
		return nil, fmt.Errorf("JWT_SECRET is not set in configuration")
	}
	cfg.JWTSecret = []byte(jwtSecretString)

	// Преобразуем строки длительности из Viper в time.Duration в структуре
	// Viper.Unmarshal с `mapstructure` и `time.Duration` должен сделать это автоматически
	// если значения в env или .env в формате time.Duration (напр. "100ms").
	// Проверим, что значения длительности не нулевые, если это не ожидается по логике.
	// Если getEnvDuration был нужен для парсинга чисел как мс, нужно адаптировать логику тут.
	// Но стандартный Viper.Unmarshal умеет парсить "100ms" в time.Duration.

	log.Printf("Конфигурация успешно загружена: %+v", cfg) // Логируем загруженную конфигурацию для проверки

	return cfg, nil
}
