package agent

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// TestCalculateOperation_Valid тестирует функцию CalculateOperation для корректных операций.
func TestCalculateOperation_Valid(t *testing.T) {
	// Определяем тестовые случаи: arg1, arg2, операция, ожидаемый результат.
	testCases := []struct {
		arg1      float64
		arg2      float64
		operation string
		expected  float64
	}{
		{2, 3, "+", 5},
		{5, 2, "-", 3},
		{3, 4, "*", 12},
		{10, 2, "/", 5},
		{7, 3, "/", 7.0 / 3.0}, // Проверка деления с плавающей точкой
		{-5, 10, "+", 5},       // Отрицательные числа
		{10, -5, "-", 15},
		{-5, -5, "*", 25},
		{-10, -2, "/", 5},
		{0, 5, "+", 5}, // Ноль как операнд
		{5, 0, "-", 5},
		{0, 5, "*", 0},
		{5, 1, "/", 5},         // Деление на 1
		{0.5, 0.25, "+", 0.75}, // Десятичные числа
		{1.0, 0.5, "-", 0.5},
		{2.5, 2.0, "*", 5.0},
		{5.0, 2.0, "/", 2.5},
		{10, 3, "-", 7},
		{100, 10, "/", 10},
		{10, 100, "/", 0.1},
	}

	// Проходим по каждому тестовому случаю
	for _, tc := range testCases {
		// Запускаем подтест для каждого случая (удобно для отчетов)
		t.Run(fmt.Sprintf("%.2f %s %.2f", tc.arg1, tc.operation, tc.arg2), func(t *testing.T) {
			// Вызываем тестируемую функцию
			actual, err := CalculateOperation(tc.arg1, tc.arg2, tc.operation)

			// Проверяем, что не было ошибки
			if err != nil {
				t.Errorf("Для операции %.2f %s %.2f: Ожидался nil error, но получен: %v", tc.arg1, tc.operation, tc.arg2, err)
				return // Если была ошибка, нет смысла проверять результат
			}

			// Сравниваем полученный результат с ожидаемым.
			// Важно сравнивать числа с плавающей точкой с некоторой погрешностью из-за их представления в памяти.
			tolerance := 1e-9 // Определяем допустимую погрешность
			if math.Abs(actual-tc.expected) > tolerance {
				t.Errorf("Для операции %.2f %s %.2f: Ожидалось %.10f, но получено %.10f (погрешность > %.10f)",
					tc.arg1, tc.operation, tc.arg2, tc.expected, actual, tolerance)
			}

			// Если дошли сюда и нет вызовов t.Error/t.Errorf, подтест считается успешным.
		})
	}
}

// TestCalculateOperation_Invalid тестирует функцию CalculateOperation для некорректных операций.
func TestCalculateOperation_Invalid(t *testing.T) {
	// Определяем тестовые случаи: arg1, arg2, операция, ожидаемая подстрока ошибки.
	testCases := []struct {
		arg1          float64
		arg2          float64
		operation     string
		expectedError string // Ожидаемая подстрока в сообщении об ошибке
	}{
		{10, 0, "/", "деление на ноль"},           // Деление на ноль
		{0, 0, "/", "деление на ноль"},            // Деление на ноль (случай 0/0)
		{5, 2, "unknown", "неизвестная операция"}, // Неизвестная операция
		{1, 1, "", "неизвестная операция"},        // Пустая строка операции
		{10, 2, "%", "неизвестная операция"},      // Операция, которой нет в switch
	}

	// Проходим по каждому тестовому случаю
	for _, tc := range testCases {
		// Запускаем подтест для каждого случая
		t.Run(fmt.Sprintf("%.2f %s %.2f", tc.arg1, tc.operation, tc.arg2), func(t *testing.T) {
			// Вызываем тестируемую функцию
			actual, err := CalculateOperation(tc.arg1, tc.arg2, tc.operation) // Здесь мы ожидаем ошибку

			// Проверяем, что ошибка была возвращена (а не nil)
			if err == nil {
				t.Errorf("Для операции %.2f %s %.2f: Ожидалась ошибка, содержащая '%s', но получен nil error. Результат: %.6f",
					tc.arg1, tc.operation, tc.arg2, tc.expectedError, actual)
				return // Если ошибки нет, дальше проверять нечего
			}

			// Проверяем, что сообщение об ошибке содержит ожидаемую подстроку
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("Для операции %.2f %s %.2f: Ожидалась ошибка, содержащая '%s', но получено '%v'.",
					tc.arg1, tc.operation, tc.arg2, tc.expectedError, err)
			}

			// Если дошли сюда и нет вызовов t.Error/t.Errorf, подтест считается успешным.
		})
	}
}
