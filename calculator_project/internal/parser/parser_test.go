// internal/parser/parser_test.go

package parser // Файл тестов находится в том же пакете, что и тестируемый код

import (
	"fmt"     // Для форматирования строк в сообщениях об ошибках
	"strings" // Для проверки подстрок в сообщениях об ошибках
	"testing" // Стандартный пакет Go для написания тестов
)

// Вспомогательная функция для сравнения двух узлов дерева (рекурсивно)
// Нам нужна эта функция, чтобы сравнить дерево, которое построил парсер,
// с тем деревом, которое мы ожидаем увидеть.
func nodesEqual(n1, n2 *Node) bool {
	// Если оба узла nil, они равны
	if n1 == nil && n2 == nil {
		return true
	}
	// Если один nil, а другой нет, они не равны
	if n1 == nil || n2 == nil {
		return false
	}
	// Если типы или значения узлов различаются, они не равны
	if n1.Type != n2.Type || n1.Value != n2.Value {
		return false
	}
	// Рекурсивно сравниваем левых и правых потомков
	if !nodesEqual(n1.Left, n2.Left) {
		return false
	}
	if !nodesEqual(n1.Right, n2.Right) {
		return false
	}
	// Если все совпадает, узлы и их поддеревья равны
	return true
}

// TestParseExpression тестирует парсер для корректных выражений.
// Названия тестовых функций в Go должны начинаться с "Test".
func TestParseExpression(t *testing.T) {
	// Определяем набор тестовых случаев.
	// Каждый случай - это структура с входной строкой и ожидаемым корневым узлом (AST).
	testCases := []struct {
		input    string // Входная строка выражения
		expected *Node  // Ожидаемое дерево разобранного выражения (Abstract Syntax Tree - AST)
	}{
		// Простой случай: сложение двух чисел
		{"1 + 2", &Node{Type: NodeTypeOperator, Value: "+",
			Left:  &Node{Type: NodeTypeNumber, Value: "1"},   // Левый потомок - число "1"
			Right: &Node{Type: NodeTypeNumber, Value: "2"}}}, // Правый потомок - число "2"

		// Простой случай: умножение двух чисел
		{"3 * 4", &Node{Type: NodeTypeOperator, Value: "*",
			Left:  &Node{Type: NodeTypeNumber, Value: "3"},
			Right: &Node{Type: NodeTypeNumber, Value: "4"}}},

		// Случай с приоритетом операций: умножение перед сложением
		// Выражение "2 + 3 * 4" должно разобрать как "2 + (3 * 4)"
		{"2 + 3 * 4", &Node{Type: NodeTypeOperator, Value: "+",
			Left: &Node{Type: NodeTypeNumber, Value: "2"}, // Левый потомок '+' - число "2"
			Right: &Node{Type: NodeTypeOperator, Value: "*", // Правый потомок '+' - узел '*'
				Left:  &Node{Type: NodeTypeNumber, Value: "3"},    // Левый потомок '*' - число "3"
				Right: &Node{Type: NodeTypeNumber, Value: "4"}}}}, // Правый потомок '*' - число "4"

		// Случай с приоритетом операций: деление перед вычитанием
		{"10 - 6 / 2", &Node{Type: NodeTypeOperator, Value: "-",
			Left: &Node{Type: NodeTypeNumber, Value: "10"},
			Right: &Node{Type: NodeTypeOperator, Value: "/",
				Left:  &Node{Type: NodeTypeNumber, Value: "6"},
				Right: &Node{Type: NodeTypeNumber, Value: "2"}}}},

		// Случай со скобками, меняющими приоритет
		// Выражение "(2 + 3) * 4" должно разобрать как "(2 + 3) * 4"
		{"(2 + 3) * 4", &Node{Type: NodeTypeOperator, Value: "*",
			Left: &Node{Type: NodeTypeOperator, Value: "+", // Левый потомок '*' - узел '+'
				Left:  &Node{Type: NodeTypeNumber, Value: "2"},
				Right: &Node{Type: NodeTypeNumber, Value: "3"}},
			Right: &Node{Type: NodeTypeNumber, Value: "4"}}}, // Правый потомок '*' - число "4"

		// Вложенные скобки
		{"( (5 + 1) * 2 ) - 3", &Node{Type: NodeTypeOperator, Value: "-",
			Left: &Node{Type: NodeTypeOperator, Value: "*",
				Left: &Node{Type: NodeTypeOperator, Value: "+",
					Left:  &Node{Type: NodeTypeNumber, Value: "5"},
					Right: &Node{Type: NodeTypeNumber, Value: "1"}},
				Right: &Node{Type: NodeTypeNumber, Value: "2"}},
			Right: &Node{Type: NodeTypeNumber, Value: "3"}}},

		// Выражение, состоящее из одного числа
		{"123.45", &Node{Type: NodeTypeNumber, Value: "123.45"}},

		// Число с явным положительным знаком
		{"+5", &Node{Type: NodeTypeNumber, Value: "+5"}},

		// Число с явным отрицательным знаком
		{"-10", &Node{Type: NodeTypeNumber, Value: "-10"}},

		// Комплексное выражение со смешанными операциями и скобками
		{"1 + 2 * (3 - 4) / 5", &Node{Type: NodeTypeOperator, Value: "+",
			Left: &Node{Type: NodeTypeNumber, Value: "1"},
			Right: &Node{Type: NodeTypeOperator, Value: "/",
				Left: &Node{Type: NodeTypeOperator, Value: "*",
					Left: &Node{Type: NodeTypeNumber, Value: "2"},
					Right: &Node{Type: NodeTypeOperator, Value: "-",
						Left:  &Node{Type: NodeTypeNumber, Value: "3"},
						Right: &Node{Type: NodeTypeNumber, Value: "4"}}},
				Right: &Node{Type: NodeTypeNumber, Value: "5"}}}},
	}

	// Проходим по каждому тестовому случаю
	for _, tc := range testCases {
		// Запускаем каждый тестовый случай как подтест для лучшего логирования
		// Название подтеста генерируем из входной строки
		t.Run(fmt.Sprintf("Input:%s", tc.input), func(t *testing.T) {
			// Создаем новый парсер для текущего входного выражения
			parserState := NewParser(tc.input)
			// Парсим выражение
			actualNode, err := parserState.ParseExpression()

			// 1. Проверяем, что парсер не вернул неожиданную ошибку
			if err != nil {
				// Если получена ошибка, но мы ожидали успешный результат, сообщаем об ошибке теста
				t.Errorf("Для выражения '%s': Парсер вернул ошибку: %v, но ожидался успешный результат.", tc.input, err)
				return // Останавливаем выполнение этого подтеста
			}

			// 2. Проверяем, что парсер обработал всю входную строку
			parserState.SkipSpaces() // Пропускаем завершающие пробелы
			if parserState.Pos < len(parserState.Input) {
				// Если после парсинга остались необработанные символы, это ошибка
				t.Errorf("Для выражения '%s': После парсинга остались необработанные символы: '%s'", tc.input, parserState.Input[parserState.Pos:])
				return // Останавливаем выполнение этого подтеста
			}

			// 3. Сравниваем полученное дерево с ожидаемым деревом с помощью вспомогательной функции
			if !nodesEqual(actualNode, tc.expected) {
				// Если деревья не совпадают, сообщаем об ошибке теста
				t.Errorf("Для выражения '%s': Дерево парсинга не совпадает.\nОжидалось: %+v\nПолучено:   %+v",
					tc.input, tc.expected, actualNode)
			}

			// Если тест дошел до сюда без вызовов t.Error или t.Errorf, он считается успешным.
		})
	}
}

// TestParseExpression_Invalid тестирует парсер для некорректных выражений.
// TestParseExpression_Invalid тестирует парсер для некорректных выражений.
func TestParseExpression_Invalid(t *testing.T) {
	// Определяем набор тестовых случаев для некорректных выражений.
	// Для некорректных выражений мы ожидаем, что парсер вернет ошибку.
	testCases := []struct {
		input string // Входная строка некорректного выражения
		// Обновлены ожидаемые подстроки в сообщениях об ошибках, чтобы соответствовать новым ошибкам парсера
		expectedError string // Ожидаемая подстрока в сообщении об ошибке
	}{
		{"1 +", "ожидалось число"},                                       // Неполное выражение (ожидалось число после +)
		{"* 2", "ожидалось число"},                                       // Оператор без левого операнда (parseExpression ожидает Term, а parseTerm ожидает Factor/Number)
		{"(2 + 3", "ожидалась закрывающая скобка"},                       // Незакрытая скобка (пойман parseFactor)
		{"2 + (3 * 4", "ожидалась закрывающая скобка"},                   // Незакрытая скобка (пойман parseFactor во вложенном вызове)
		{"2 (3 + 4)", "неожиданный символ '(' после числа"},              // <-- ОБНОВЛЕНО: Неожиданный символ после числа (пойман parseFactor)
		{"2 + * 3", "ожидалось число"},                                   // Последовательность операторов (parseTerm ожидает Factor после +, но видит *)
		{"1.2.3", "некорректный формат числа"},                           // <-- ОБНОВЛЕНО: Некорректный формат числа (пойман parseNumber через ParseFloat)
		{".", "некорректный формат числа"},                               // <-- ОБНОВЛЕНО: Некорректный формат числа (пойман parseNumber через ParseFloat)
		{"+.", "некорректный формат числа"},                              // <-- ОБНОВЛЕНО: Некорректный формат числа (пойман parseNumber через ParseFloat)
		{"abc", "ожидалось число"},                                       // Недопустимые символы (parseNumber не может распознать число)
		{"(2 + 3))", "неожиданный символ ')' после выражения в скобках"}, // <-- ОБНОВЛЕНО: Лишняя закрывающая скобка (пойман parseFactor)
		{"()", "ожидалось число"},                                        // Пустые скобки (parseFactor видит () но parseExpression ожидает Term/Number)
		{"2a", "неожиданный символ 'a' после числа"},                     // <-- ДОБАВЛЕНО/ОБНОВЛЕНО: Неожиданный символ после числа
		{"(2+3)a", "неожиданный символ 'a' после выражения в скобках"},   // <-- ДОБАВЛЕНО/ОБНОВЛЕНО: Неожиданный символ после ()
	}

	// Проходим по каждому тестовому случаю для некорректных выражений
	for _, tc := range testCases {
		// Запускаем каждый тестовый случай как подтест
		t.Run(fmt.Sprintf("Input:%s", tc.input), func(t *testing.T) {
			parserState := NewParser(tc.input)
			_, err := parserState.ParseExpression() // Здесь мы ожидаем ошибку

			// Проверяем, что ошибка была возвращена (теперь это должно всегда выполняться, если парсер работает правильно)
			if err == nil {
				t.Errorf("Для выражения '%s': Ожидалась ошибка, содержащая '%s', но парсер завершился без ошибки.",
					tc.input, tc.expectedError)
				// Не return здесь, чтобы увидеть сообщение об ошибке ниже, если оно все же было nil (чего быть не должно)
			} else {
				// Если ошибка была возвращена, проверяем ее сообщение
				t.Logf("Для выражения '%s': Получена ошибка: %v (Ожидалась подстрока '%s')", tc.input, err, tc.expectedError) // Выводим полученную ошибку для отладки
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("Для выражения '%s': Ожидалась ошибка, содержащая '%s', но получено '%v'.",
						tc.input, tc.expectedError, err)
				}
			}
		})
	}
}
