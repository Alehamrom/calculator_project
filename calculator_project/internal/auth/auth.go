package auth // Объявляем пакет auth

import (
	"context"
	// "database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	// "time"

	// Локальные импорты
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

// AuthMiddleware: Middleware функция для проверки JWT токена в заголовке Authorization.
// Принимает секретный ключ для проверки подписи токена и следующий http.Handler в цепочке.
// Возвращает новый http.Handler (нашу middleware функцию).
func AuthMiddleware(jwtSecret string) func(next http.Handler) http.Handler {
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

				// Временно отключил этот блок
				// if ve, ok := err.(*jwt.ValidationError); ok {
				// 	if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// 		localHTTP.RespondError(w, http.StatusUnauthorized, "Token is expired") // Токен истек
				// 		return
				// 	}
				// }

				localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid token") // Любая ошибка валидации
				return
			}

			// 3. Извлекаем claims из валидного токена.
			claims, ok := token.Claims.(*localModels.CustomClaims)
			if !ok || !token.Valid {
				// Если тип claims не соответствует или токен по какой-то причине не валиден после парсинга.
				log.Println("AuthMiddleware: Неверный формат claims или токен не валиден после парсинга.")
				localHTTP.RespondError(w, http.StatusUnauthorized, "Invalid token claims")
				return
			}

			// 4. Если токен валиден и claims извлечены, добавляем информацию о пользователе.
			// Создаем новый контекст, копируя старый и добавляя наше значение по нашему ключу.
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
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
