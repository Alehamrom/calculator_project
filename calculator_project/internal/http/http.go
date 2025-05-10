package http // Объявляем пакет http (внутри internal)

import (
	"encoding/json" // Для работы с JSON
	"log"           // Для логирования ошибок
	"net/http"      // Для работы с HTTP
)

// RespondJSON: Отправляет HTTP-ответ в формате JSON с указанным статус кодом и телом (payload).
// payload - это структура или другое значение, которое будет преобразовано в JSON.
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	// Сначала полностью маршалируем (преобразуем в JSON-байты) тело ответа.
	response, err := json.Marshal(payload)
	if err != nil {
		// Если маршалирование не удалось (например, структура содержит циклические ссылки, что редкость),
		// логируем эту внутреннюю ошибку сервера.
		log.Printf("Ошибка при маршалировании JSON ответа: %v", err)
		// И отправляем стандартизированный ответ об внутренней ошибке сервера (500).
		// Используем RespondError, чтобы быть последовательными.
		RespondError(w, http.StatusInternalServerError, "Internal Server Error")
		return // Завершаем выполнение функции
	}

	// Если маршалирование прошло успешно, теперь можно безопасно установить заголовки,
	// статус и записать готовое JSON-тело.
	w.Header().Set("Content-Type", "application/json") // Устанавливаем Content-Type
	w.WriteHeader(status)                              // Устанавливаем HTTP статус код
	w.Write(response)                                  // Записываем готовые JSON-байты в тело ответа
}

// RespondError: Отправляет стандартизированный JSON-ответ об ошибке с указанным статус кодом и сообщением.
// Формат ошибки согласно условию проекта: {"error": "сообщение об ошибке"}.
func RespondError(w http.ResponseWriter, status int, message string) {
	// Создаем структуру (карту) для тела ответа об ошибке.
	errorResponse := map[string]string{"error": message}
	// Используем RespondJSON для отправки этого тела об ошибке.
	// В данном случае payload (errorResponse) - это простая карта, которая всегда успешно маршалируется в JSON.
	// Если RespondJSON вдруг вернет ошибку при маршалировании errorResponse (крайне маловероятно),
	// оно само обработает это как внутреннюю ошибку.
	RespondJSON(w, status, errorResponse)
}

// Этот файл следует сохранить как internal/http/http.go
// Убедись, что у тебя установлена библиотека log (входит в стандартную библиотеку Go) и encoding/json, net/http.
