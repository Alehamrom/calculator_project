package http

import (
	"encoding/json"
	"log"
	"net/http"
)

// RespondJSON отправляет HTTP-ответ в формате JSON.
// Принимает http.ResponseWriter, статус код и данные для кодирования в JSON.
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	// Кодируем данные payload в JSON байты.
	response, err := json.Marshal(payload)
	if err != nil {
		// Если при кодировании произошла ошибка, логируем ее.
		log.Printf("Ошибка маршалинга JSON ответа: %v", err)
		// И отправляем ответ об внутренней ошибке сервера.
		RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Устанавливаем заголовок, статус код и записываем JSON в тело ответа.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(response)
	if err != nil {
		// Логируем ошибку, если не удалось записать ответ.
		log.Printf("Ошибка записи JSON ответа в ResponseWriter: %v", err)
		// В этом случае статус уже отправлен, дополнительный ответ об ошибке невозможен.
	}
}

// RespondError отправляет стандартизированный JSON-ответ об ошибке.
func RespondError(w http.ResponseWriter, status int, message string) {
	// Готовим структуру для ответа об ошибке.
	errorResponse := map[string]string{"error": message}
	RespondJSON(w, status, errorResponse)
}
