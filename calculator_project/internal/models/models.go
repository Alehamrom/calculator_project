package models

import "github.com/golang-jwt/jwt/v5"

// CustomClaims: Структура для дополнительных данных в JWT токене (payload).
type CustomClaims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}
