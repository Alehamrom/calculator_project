package auth // Объявляем пакет auth

import (
	"fmt"                        // Для форматирования ошибок
	"golang.org/x/crypto/bcrypt" // Импортируем библиотеку bcrypt
)

// HashPassword: Генерирует bcrypt-хеш пароля в виде строки.
// Возвращает хеш и ошибку, если хеширование не удалось.
func HashPassword(password string) (string, error) {
	// bcrypt.GenerateFromPassword принимает пароль в виде байт []byte и "стоимость" (cost).
	// bcrypt.DefaultCost обеспечивает хороший баланс между безопасностью и производительностью.
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Если при хешировании возникла ошибка, возвращаем ее.
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	// Преобразуем полученные байты хеша обратно в строку для хранения.
	return string(bytes), nil
}

// CheckPasswordHash: Сравнивает обычный (нехешированный) пароль с bcrypt-хешем.
// Возвращает true, если пароль совпадает с хешем, false в противном случае.
func CheckPasswordHash(password, hash string) bool {
	// bcrypt.CompareHashAndPassword сравнивает байты хеша с байтами пароля.
	// Эта функция сама выполняет хеширование предоставленного пароля и сравнивает его с хешем.
	// Она возвращает nil, если пароли совпадают, или ошибку, если не совпадают или хеш некорректен.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// Возвращаем true, если ошибка равна nil (пароли совпали), и false в противном случае.
	return err == nil
}

// TODO: В этом пакете также может быть логика для работы с JWT токенами.
