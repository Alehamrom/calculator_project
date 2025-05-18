package agent // Этот файл будет частью пакета 'agent'

import (
	"errors"
	"fmt"
)

// CalculateOperation выполняет арифметическую операцию над двумя числами.
// Принимает операнды как float64 и строку оператора.
// Возвращает результат вычисления (float64) и ошибку (error),
// например, при делении на ноль или неизвестной операции.
func CalculateOperation(arg1, arg2 float64, operation string) (float64, error) {
	switch operation {
	case "+":
		return arg1 + arg2, nil
	case "-":
		return arg1 - arg2, nil
	case "*":
		return arg1 * arg2, nil
	case "/":
		if arg2 == 0 {
			// Возвращаем ошибку при делении на ноль.
			// Результат в этом случае может быть 0.0 или NaN, но главное - вернуть ошибку.
			return 0.0, errors.New("деление на ноль")
		}
		return arg1 / arg2, nil
	default:
		// Возвращаем ошибку для любой другой операции.
		return 0.0, fmt.Errorf("неизвестная операция: %s", operation)
	}
}
