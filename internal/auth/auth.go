package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	localHTTP "calculator_project/internal/http"
	localModels "calculator_project/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// UserIDContextKey: Специальный тип для ключа контекста, чтобы избежать конфликтов.
type UserIDContextKey string

// UserIDKey: Константа для ключа, по которому UserID будет храниться в контексте запроса.
const UserIDKey UserIDContextKey = "userID"

func ContextWithUserID(ctx context.Context, userID int64) context.Context {
	// context.WithValue возвращает новый контекст, который содержит ключ/значение.
	return context.WithValue(ctx, UserIDKey, userID) // Используем константу UserIDKey
}

// GenerateJWT генерирует JWT токен для данного пользователя.
// Принимает ID пользователя (int) и секретный ключ ([]byte).
// Возвращает строку с токеном или ошибку.
func GenerateJWT(userID int64, secret []byte) (string, error) {
	// Определяем срок действия токена, например, 24 часа с текущего момента.
	expirationTime := time.Now().Add(24 * time.Hour)

	// Создаем claims (набор данных), которые будут закодированы в токене.
	claims := &localModels.CustomClaims{
		UserID: int64(userID), // Добавляем ID пользователя в claims
		RegisteredClaims: jwt.RegisteredClaims{
			// Добавляем стандартные claims, рекомендованные JWT спецификацией.
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Время истечения срока действия
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // Время выпуска токена
		},
	}

	// Создаем новый токен.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен нашим секретным ключом.
	// Метод SignedString возвращает строку с закодированным токеном.
	tokenString, err := token.SignedString(secret)
	if err != nil {
		// Если при подписи возникла ошибка.
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Возвращаем сгенерированную строку токена и nil ошибку.
	return tokenString, nil
}

// ValidateJWT валидирует JWT токен и извлекает UserID из claims.
func ValidateJWT(tokenString string, secret []byte) (int64, error) {
	// Парсим токен и одновременно валидируем его.
	token, err := jwt.ParseWithClaims(tokenString, &localModels.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// Если метод подписи не HMAC, возвращаем ошибку.
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Если метод подписи правильный, возвращаем наш секретный ключ (в виде []byte) для проверки подписи.
		return secret, nil // Используем переданный в ValidateJWT секретный ключ
	})

	// Проверяем ошибки, которые могли возникнуть при парсинге и валидации токена (неверная подпись, истек срок и т.д.).
	if err != nil {
		// В случае любой ошибки валидации (формат, подпись, срок действия и т.д.),
		// возвращаем 0 (или -1) как UserID и саму ошибку.
		return 0, fmt.Errorf("token validation failed: %w", err)
	}

	// Если парсинг и валидация прошли без ошибки, пытаемся извлечь наши claims.
	claims, ok := token.Claims.(*localModels.CustomClaims)

	// Дополнительно проверяем, что извлеченные claims имеют ожидаемый тип (наша структура CustomClaims)
	// И что токен в целом помечен как Valid после вызова ParseWithClaims (хотя если err == nil, token.Valid почти всегда true).
	if !ok || !token.Valid {
		// Если claims не нашего типа или токен по какой-то неочевидной причине не валиден.
		return 0, errors.New("invalid token claims or token not valid after parsing")
	}

	// Если все успешно, возвращаем UserID из claims.
	return claims.UserID, nil // Возвращаем ID пользователя из claims
}

// AuthMiddleware: Middleware функция для проверки JWT токена в заголовке Authorization.
// Принимает секретный ключ для проверки подписи токена и следующий http.Handler в цепочке.
// Возвращает новый http.Handler (нашу middleware функцию).
func AuthMiddleware(jwtSecret []byte) func(next http.Handler) http.Handler {
	// Возвращаем саму middleware функцию, которая будет принимать следующий хэндлер.
	return func(next http.Handler) http.Handler {
		// Возвращаем анонимную функцию, которая реализует интерфейс http.Handler (ServeHTTP).
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Этот код выполняется при каждом входящем запросе к защищенным маршрутам.

			// 1. Извлекаем токен из заголовка Authorization.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Println("AuthMiddleware: Заголовок Authorization отсутствует.")
				localHTTP.RespondError(w, http.StatusUnauthorized, "Authorization header is required")
				return
			}

			// Проверяем формат заголовка "Bearer ".
			headerParts := strings.Split(authHeader, " ")
			if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
				// Если формат неверный.
				log.Println("AuthMiddleware: Неверный формат заголовка Authorization.")
				localHTTP.RespondError(w, http.StatusUnauthorized, "Authorization header must be in format 'Bearer <token>'")
				return
			}

			tokenString := headerParts[1] // Извлекаем сам токен (часть после "Bearer ")

			// 2. Парсим и валидируем токен.
			// jwt.ParseWithClaims парсит токен и одновременно проверяет его подпись и стандартные claims.
			// Вторым аргументом передаем пустой экземпляр нашей структуры claims из пакета models.
			// Третьим аргументом - Keyfunc: функция, которая предоставляет секретный ключ для проверки подписи.
			token, err := jwt.ParseWithClaims(tokenString, &localModels.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					log.Printf("AuthMiddleware: Неожиданный метод подписи токена: %v", token.Header["alg"])
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				// Возвращаем секретный ключ в виде байтов.
				return []byte(jwtSecret), nil
			})

			if err != nil {
				// Если парсинг или валидация токена не удались, возвращаем 401.
				log.Printf("AuthMiddleware: Ошибка валидации токена: %v", err)

				localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid token") // Любая ошибка валидации
				return
			}

			// 3. Извлекаем claims из валидного токена.
			claims, ok := token.Claims.(*localModels.CustomClaims)
			if !ok || !token.Valid {
				// Если тип claims не соответствует или токен по какой-то причине не валиден после парсинга.
				log.Println("AuthMiddleware: Неверный формат claims или токен не валиден после парсинга.")
				localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid token claims")
				return // Выходим
			}

			// 4. Если токен валиден и claims извлечены, добавляем информацию о пользователе в контекст.
			// Создаем новый контекст, копируя старый и добавляя ID пользователя из claims токена по нашему ключу.
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID) // <--- ИСПОЛЬЗУЕМ claims.UserID!
			r = r.WithContext(ctx)

			// 5. Передаем запрос дальше по цепочке обработчиков.
			next.ServeHTTP(w, r)
		})
	}
}

func GetUserIDFromContext(ctx context.Context) (int64, bool) {
	userID, ok := ctx.Value(UserIDKey).(int64)
	return userID, ok
}
