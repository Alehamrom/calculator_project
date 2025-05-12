package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// NodeType представляет тип узла в разобранном выражении.
type NodeType int

const (
	NodeTypeNumber   NodeType = iota // Узел представляет число
	NodeTypeOperator                 // Узел представляет оператор
)

type Node struct {
	Type  NodeType // Тип узла (число или оператор)
	Value string   // Значение узла (строка числа или оператор)
	Left  *Node    // Левый потомок (для операторов)
	Right *Node    // Правый потомок (для операторов)
}

// ParserState хранит состояние парсера во время разбора.
type ParserState struct {
	Input string
	Pos   int
}

// NewParser создает новый экземпляр ParserState.
func NewParser(expression string) *ParserState {
	return &ParserState{Input: strings.TrimSpace(expression), Pos: 0}
}

// ParseExpression парсит выражение и возвращает корневой узел разобранного дерева.
// Это основная функция парсинга.
func (p *ParserState) ParseExpression() (*Node, error) {
	node, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for {
		p.SkipSpaces()
		// Проверяем операторы сложения и вычитания (+, -) с более низким приоритетом.
		if p.Pos < len(p.Input) && (p.Input[p.Pos] == '+' || p.Input[p.Pos] == '-') {
			operator := string(p.Input[p.Pos])
			p.Pos++
			rightNode, err := p.parseTerm() // Парсим следующий терм
			if err != nil {
				return nil, err
			}
			// Создаем узел для оператора. Его левый потомок - текущий результат, правый - результат parseTerm.
			// Пример: для A + B, узел '+' будет иметь левого потомка 'A' и правого потомка 'B'.
			// Для A + B + C, сначала создается узел '+' с потомками 'A' и 'B', затем новый узел '+' с потомками (A+B) и 'C'.
			newNode := &Node{
				Type:  NodeTypeOperator,
				Value: operator,
				Left:  node,      // Левый потомок - предыдущий узел или число
				Right: rightNode, // Правый потомок - результат следующего терма
			}
			node = newNode // Обновляем текущий узел дерева
		} else {
			break // Нет операторов '+' или '-', выходим из цикла
		}
	}
	return node, nil // Возвращаем корневой узел разобранного подвыражения
}

// parseTerm парсит термы (множители и делители) в выражении.
func (p *ParserState) parseTerm() (*Node, error) {
	node, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for {
		p.SkipSpaces()
		// Проверяем операторы умножения и деления (*, /) с более высоким приоритетом.
		if p.Pos < len(p.Input) && (p.Input[p.Pos] == '*' || p.Input[p.Pos] == '/') {
			operator := string(p.Input[p.Pos])
			p.Pos++
			rightNode, err := p.parseFactor() // Парсим следующий фактор
			if err != nil {
				return nil, err
			}
			// Создаем узел для оператора.
			newNode := &Node{
				Type:  NodeTypeOperator,
				Value: operator,
				Left:  node,      // Левый потомок - предыдущий узел или число
				Right: rightNode, // Правый потомок - результат следующего фактора
			}
			node = newNode // Обновляем текущий узел дерева
		} else {
			break // Нет операторов '*' или '/', выходим из цикла
		}
	}
	return node, nil // Возвращаем корневой узел разобранного подтерма
}

// parseFactor парсит факторы (числа или выражения в скобках).
func (p *ParserState) parseFactor() (*Node, error) {
	p.SkipSpaces()
	if p.Pos < len(p.Input) && p.Input[p.Pos] == '(' {
		p.Pos++
		node, err := p.ParseExpression() // Рекурсивно парсим вложенное выражение
		if err != nil {
			return nil, err
		}
		p.SkipSpaces()
		if p.Pos >= len(p.Input) || p.Input[p.Pos] != ')' {
			return nil, errors.New("ожидалась закрывающая скобка")
		}
		p.Pos++
		return node, nil // Возвращаем корневой узел вложенного выражения
	}
	// Если это не скобки, парсим число
	return p.parseNumber()
}

// parseNumber парсит числовое значение.
func (p *ParserState) parseNumber() (*Node, error) {
	p.SkipSpaces()
	start := p.Pos
	// Разрешаем опциональный знак в начале числа
	if p.Pos < len(p.Input) && (p.Input[p.Pos] == '+' || p.Input[p.Pos] == '-') {
		p.Pos++
	}
	// Числа могут содержать цифры и одну десятичную точку
	for p.Pos < len(p.Input) && (unicode.IsDigit(rune(p.Input[p.Pos])) || p.Input[p.Pos] == '.') {
		p.Pos++
	}

	if start == p.Pos {
		return nil, errors.New("ожидалось число")
	}
	numberStr := p.Input[start:p.Pos]

	// Простая валидация числа (можно улучшить)
	if strings.Count(numberStr, ".") > 1 {
		return nil, errors.New("некорректное число: " + numberStr + " (более одной десятичной точки)")
	}
	if numberStr == "." || numberStr == "+" || numberStr == "-" || numberStr == "+." || numberStr == "-." {
		return nil, errors.New("некорректное число: " + numberStr)
	}

	// Пробуем преобразовать строку в число, чтобы убедиться в валидности формата числа
	if _, err := strconv.ParseFloat(numberStr, 64); err != nil {
		return nil, fmt.Errorf("некорректный формат числа: %s", numberStr)
	}

	// Возвращаем узел типа "число" со строковым значением числа
	return &Node{Type: NodeTypeNumber, Value: numberStr}, nil
}

// skipSpaces пропускает пробелы.
func (p *ParserState) SkipSpaces() {
	for p.Pos < len(p.Input) && unicode.IsSpace(rune(p.Input[p.Pos])) {
		p.Pos++
	}
}

// match проверяет, совпадает ли текущий символ с ожидаемым.
func (p *ParserState) match(ch byte) bool {
	return p.Pos < len(p.Input) && p.Input[p.Pos] == ch
}

// --- Функция для обхода дерева и создания задач ---

// CalculationTask (повторяет структуру из handlers, возможно, стоит вынести в models)
type CalculationTask struct {
	ID           string // UUID задачи
	Operation    string // Операция (например, "+", "*", "/", или даже "number" для операндов?)
	Arg1         string // Первый аргумент (число или ID задачи, от которой зависит этот аргумент)
	Arg2         string // Второй аргумент (число или ID задачи, от которой зависит этот аргумент)
	ExpressionID string // Связь с выражением (заполняется при сохранении в БД)
	Status       string // Статус задачи (Pending, In Progress, Completed, Failed)
	// TODO: Поля для зависимостей?
}

// NodeToTasks рекурсивно обходит дерево узлов выражения и формирует список задач.
// Возвращает список задач и ID узла (или значение), представляющего результат текущего поддерева.
// Для чисел возвращает само число как "результат", для операторов возвращает ID задачи.
func NodeToTasks(node *Node, tasks *[]CalculationTask) (string, error) {
	if node == nil {
		return "", errors.New("обход дерева: обнаружен nil узел")
	}

	if node.Type == NodeTypeNumber {
		// Если узел - число, его "результат" - само число (переданное как строка).
		// Для агента это будет просто операнд.
		return node.Value, nil
	}

	if node.Type == NodeTypeOperator {
		// Если узел - оператор, сначала рекурсивно обрабатываем его потомков.
		// Результаты потомков станут аргументами для текущей задачи.
		// Arg1Result и Arg2Result будут либо строкой числа, либо ID задачи, которая вычисляет этот аргумент.
		arg1Result, err := NodeToTasks(node.Left, tasks)
		if err != nil {
			return "", fmt.Errorf("обход дерева: ошибка при обработке левого потомка: %w", err)
		}
		arg2Result, err := NodeToTasks(node.Right, tasks)
		if err != nil {
			return "", fmt.Errorf("обход дерева: ошибка при обработке правого потомка: %w", err)
		}

		// Создаем задачу для текущей операции.
		taskID := uuid.New().String() // Генерируем уникальный ID для этой задачи

		newTask := CalculationTask{
			ID:        taskID,
			Operation: node.Value, // Оператор (+, -, *, /)
			Arg1:      arg1Result, // Результат левого потомка (число или ID задачи)
			Arg2:      arg2Result, // Результат правого потомка (число или ID задачи)
			Status:    "Pending",  // Начальный статус задачи
			// ExpressionID будет заполнен позже при сохранении
		}
		*tasks = append(*tasks, newTask) // Добавляем сгенерированную задачу в список задач

		// Результат этой задачи - это ее собственный ID.
		return taskID, nil
	}

	return "", errors.New("обход дерева: необработанный тип узла")
}

/*
func IsTaskID(arg string) bool {
	_, err := uuid.Parse(arg)
	return err == nil
}
*/
