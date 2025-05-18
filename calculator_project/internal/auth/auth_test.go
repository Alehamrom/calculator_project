// internal/auth/auth_test.go
package auth // Файл тестов находится в том же пакете 'auth'

import (
	"fmt"
	"strings" // Для проверки подстроки в ошибках
	"testing" // Стандартный пакет Go для тестов
	"time"    // Для работы со временем (особенно для тестов JWT)

	// Важно: убедись, что у тебя в проекте используется библиотека github.com/golang-jwt/jwt/v5
	// Именно ее типы и функции (например, jwt.MapClaims, jwt.NewWithClaims, jwt.SigningMethodHS256)
	// используются для тестирования токенов. Если ты использовал другую библиотеку, тесты нужно будет адаптировать.
	"github.com/golang-jwt/jwt/v5"
)

// Используем тестовый секретный ключ для JWT. В реальном коде этот ключ должен быть надежным.
var testSecret = []byte("very_secret_test_key_for_jwt") // Длинный и уникальный для тестов

// TestHashPassword тестирует функцию HashPassword.
func TestHashPassword(t *testing.T) {
	password := "securepassword123"
	hashedPassword, err := HashPassword(password)

	// Проверяем, что при хэшировании не возникло ошибки.
	if err != nil {
		t.Errorf("HashPassword вернула ошибку для пароля '%s': %v", password, err)
	}

	// Проверяем, что функция вернула непустую строку (сам хэш).
	if hashedPassword == "" {
		t.Errorf("HashPassword вернула пустую строку для пароля '%s'", password)
	}

	// Примечание: Мы не проверяем точное значение хэша, потому что он включает соль и каждый раз будет разным.
	// Правильность хэширования/сравнения проверяется в TestCheckPasswordHash.
}

// TestCheckPasswordHash тестирует функцию CheckPasswordHash.
// Эта функция проверяет, соответствует ли предоставленный пароль хэшу.
func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword" // Пароль для теста

	// Сначала генерируем хэш для тестового пароля.
	hashedPassword, err := HashPassword(password)
	if err != nil {
		// Если не удалось сгенерировать хэш, дальше тестировать CheckPasswordHash бессмысленно.
		t.Fatalf("Не удалось сгенерировать хэш для теста CheckPasswordHash: %v", err)
	}

	// Тестовый случай 1: Корректный пароль и корректный хэш. Ожидаем true.
	if !CheckPasswordHash(password, hashedPassword) {
		t.Errorf("CheckPasswordHash вернула false для корректной пары пароль/хэш")
	}

	// Тестовый случай 2: Некорректный пароль с корректным хэшем. Ожидаем false.
	wrongPassword := "wrongpassword"
	if CheckPasswordHash(wrongPassword, hashedPassword) {
		t.Errorf("CheckPasswordHash вернула true для некорректного пароля")
	}

	// Тестовый случай 3: Пустая строка пароля. Ожидаем false.
	if CheckPasswordHash("", hashedPassword) {
		t.Errorf("CheckPasswordHash вернула true для пустого пароля")
	}

	// Тестовый случай 4: Пустая строка хэша. Ожидаем false.
	if CheckPasswordHash(password, "") {
		t.Errorf("CheckPasswordHash вернула true для пустого хэша")
	}

	// Тестовый случай 5: Хэш некорректного формата (не является валидным bcrypt хэшем). Ожидаем false.
	// При проверке такого хэша bcrypt должна вернуть ошибку, а наша функция - false.
	invalidHash := "thisisnotavalidhashformat"
	if CheckPasswordHash(password, invalidHash) {
		t.Errorf("CheckPasswordHash вернула true для некорректного формата хэша")
	}
}

// TestGenerateJWT тестирует функцию GenerateJWT.
func TestGenerateJWT(t *testing.T) {
	userID := 123 // Тестовый UserID
	tokenString, err := GenerateJWT(int64(userID), testSecret)

	// Проверяем, что при генерации токена не возникло ошибки.
	if err != nil {
		t.Errorf("GenerateJWT вернула ошибку для UserID %d: %v", userID, err)
	}

	// Проверяем, что функция вернула непустую строку токена.
	if tokenString == "" {
		t.Errorf("GenerateJWT вернула пустую строку токена для UserID %d", userID)
	}

	// Опционально: Пытаемся разобрать сгенерированный токен без проверки подписи,
	// чтобы проверить его структуру и наличие нужных claims (полей данных).
	// Это предполагает использование github.com/golang-jwt/jwt/v5.
	token, _, parseErr := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if parseErr != nil {
		t.Errorf("Не удалось разобрать сгенерированный токен '%s': %v", tokenString, parseErr)
		return // Если токен не разобрать, дальше проверять claims бессмысленно.
	}

	// Проверяем, что claims имеют ожидаемый тип (MapClaims).
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Errorf("Ожидались claims типа jwt.MapClaims, но получено: %T", token.Claims)
		return
	}

	// Проверяем наличие и значение claim 'user_id'. JWT числа часто парсятся как float64.
	userIDClaim, ok := claims["user_id"].(float64)
	if !ok {
		t.Errorf("Ожидался claim 'user_id' типа float64, но получено: %T (значение: %v)", claims["user_id"], claims["user_id"])
	} else if int(userIDClaim) != userID {
		t.Errorf("Ожидалось значение UserID в claim 'user_id' %d, но получено %.0f", userID, userIDClaim)
	}

	// Опционально: Проверяем наличие стандартных claims, если твоя GenerateJWT их добавляет (exp, iat, sub).
	// Их наличие зависит от реализации.
	if _, ok := claims["exp"]; !ok {
		t.Log("Предупреждение: Claim 'exp' отсутствует в токене (возможно, так задумано GenerateJWT)")
	}
	if _, ok := claims["iat"]; !ok {
		t.Log("Предупреждение: Claim 'iat' отсутствует в токене (возможно, так задумано GenerateJWT)")
	}
	if _, ok := claims["sub"]; !ok {
		t.Log("Предупреждение: Claim 'sub' отсутствует в токене (возможно, так задумано GenerateJWT)")
	}
}

// TestValidateJWT тестирует функцию ValidateJWT.
func TestValidateJWT(t *testing.T) {
	userID := 99                          // Тестовый UserID
	secret := testSecret                  // Секретный ключ, использованный для генерации токена
	wrongSecret := []byte("wrong_secret") // Другой, некорректный секретный ключ

	// --- Тестовые случаи с валидным токеном ---

	// Генерируем валидный токен для UserID и секретного ключа.
	validTokenString, err := GenerateJWT(int64(userID), secret)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать валидный токен для теста ValidateJWT: %v", err)
	}

	// Тестовый случай 1.1: Валидный токен с корректным секретом. Ожидаем nil error и правильный UserID.
	validatedUserID, validateErr := ValidateJWT(validTokenString, secret)
	if validateErr != nil {
		t.Errorf("ValidateJWT вернула ошибку для валидного токена с корректным секретом: %v", validateErr)
	}

	expectedUserID := int64(userID)
	if validatedUserID != expectedUserID {
		t.Errorf("ValidateJWT вернула UserID %d для валидного токена, ожидалось %d", validatedUserID, userID)
	}

	// --- Тестовые случаи с некорректными токенами/секретами ---

	// Тестовый случай 2.1: Некорректная строка токена (не формат JWT). Ожидаем ошибку.
	invalidTokenString := "это.не.является.jwt.токеном"
	validatedUserID, validateErr = ValidateJWT(invalidTokenString, secret)
	if validateErr == nil {
		t.Errorf("ValidateJWT вернула nil error для некорректного формата токена")
	}
	// Проверяем, что сообщение об ошибке содержит ожидаемую подстроку.
	// Подстрока может зависеть от реализации библиотеки JWT.
	if validateErr != nil &&
		!strings.Contains(validateErr.Error(), "token is invalid") && // Исходная проверка
		!strings.Contains(validateErr.Error(), "недействителен") && // Исходная проверка (рус.)
		!strings.Contains(validateErr.Error(), "token is malformed") {
		t.Errorf("Ожидалась ошибка валидации токена (например, 'invalid token' или 'token is malformed'), но получена '%v'", validateErr)
	}
	// Ожидаем, что при ошибке валидации UserID будет 0 или -1 (в зависимости от реализации ValidateJWT).
	if validatedUserID != 0 && validatedUserID != -1 {
		t.Logf("ValidateJWT вернула UserID %d для некорректного формата токена (ожидалось 0 или -1)", validatedUserID) // Используем Logf, т.к. возвращаемое значение при ошибке может варьироваться
	}

	// Тестовый случай 2.2: Валидный токен с НЕкорректным секретом. Ожидаем ошибку подписи.
	validatedUserID, validateErr = ValidateJWT(validTokenString, wrongSecret)
	if validateErr == nil {
		t.Errorf("ValidateJWT вернула nil error для токена с некорректным секретом")
	}
	// Проверяем, что сообщение об ошибке содержит ожидаемую подстроку (связанную с подписью).
	// Подстрока может зависеть от реализации библиотеки JWT.
	if validateErr != nil && !strings.Contains(validateErr.Error(), "signature is invalid") && !strings.Contains(validateErr.Error(), "неверная подпись") {
		t.Errorf("Ожидалась ошибка подписи токена, но получена '%v'", validateErr)
	}
	// Ожидаем, что при ошибке валидации UserID будет 0 или -1.
	if validatedUserID != 0 && validatedUserID != -1 {
		t.Logf("ValidateJWT вернула UserID %d для токена с некорректным секретом (ожидалось 0 или -1)", validatedUserID) // Используем Logf
	}

	// Тестовый случай 2.3: Токен с некорректным типом claim 'user_id'. Ожидаем ошибку.
	// Вручную создаем токен с claim 'user_id', который не float64 (например, строка).
	invalidClaims := jwt.MapClaims{
		"user_id": "не число",                       // User ID как строка - некорректный тип
		"exp":     time.Now().Add(time.Hour).Unix(), // Валидный срок
		"iat":     time.Now().Unix(),
		"sub":     fmt.Sprintf("%d", userID),
	}
	invalidClaimToken := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidClaims)
	// Подписываем корректным секретом (сама подпись будет валидна, но claims некорректны).
	invalidClaimTokenString, _ := invalidClaimToken.SignedString(secret)

	validatedUserID, validateErr = ValidateJWT(invalidClaimTokenString, secret)
	if validateErr == nil {
		t.Errorf("ValidateJWT вернула nil error для токена с некорректным типом claim 'user_id'")
	}
	// Проверяем, что сообщение об ошибке содержит ожидаемую подстроку (связанную с типом claim).
	if validateErr != nil && !strings.Contains(validateErr.Error(), "incorrect type") && !strings.Contains(validateErr.Error(), "некорректный тип") && !strings.Contains(validateErr.Error(), "claim") {
		t.Errorf("Ожидалась ошибка типа claim 'user_id', но получена '%v'", validateErr)
	}
	// Ожидаем, что при ошибке валидации UserID будет 0 или -1.
	if validatedUserID != 0 && validatedUserID != -1 {
		t.Logf("ValidateJWT вернула UserID %d для токена с некорректным типом claim 'user_id' (ожидалось 0 или -1)", validatedUserID) // Используем Logf
	}

	// Тестовый случай 2.4: Просроченный токен. Ожидаем ошибку.
	// Создаем токен, срок действия которого истек в прошлом.
	expiredClaims := jwt.MapClaims{
		"user_id": float64(userID),
		"exp":     time.Now().Add(-time.Hour).Unix(), // Срок действия истек час назад
		"iat":     time.Now().Add(-2 * time.Hour).Unix(),
		"sub":     fmt.Sprintf("%d", userID),
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	// Подписываем корректным секретом.
	expiredTokenString, _ := expiredToken.SignedString(secret)

	validatedUserID, validateErr = ValidateJWT(expiredTokenString, secret)
	if validateErr == nil {
		t.Errorf("ValidateJWT вернула nil error для просроченного токена")
	}
	// Проверяем, что сообщение об ошибке содержит ожидаемую подстроку (связанную со сроком действия).
	if validateErr != nil && !strings.Contains(validateErr.Error(), "token has invalid claims") && !strings.Contains(validateErr.Error(), "expired") && !strings.Contains(validateErr.Error(), "просрочен") {
		t.Errorf("Ожидалась ошибка просроченного токена, но получена '%v'", validateErr)
	}
	// Ожидаем, что при ошибке валидации UserID будет 0 или -1.
	if validatedUserID != 0 && validatedUserID != -1 {
		t.Logf("ValidateJWT вернула UserID %d для просроченного токена (ожидалось 0 или -1)", validatedUserID) // Используем Logf
	}

	// TODO: Можно добавить тесты для токенов, срок действия которых начнется в будущем (nbf - not before).
}
