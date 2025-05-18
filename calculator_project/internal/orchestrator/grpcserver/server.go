package grpcserver

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp" // !!! ДОБАВЬ ЭТОТ ИМПОРТ !!!
	"strconv"

	//"strings" // Возможно, уже есть, но может понадобиться
	//"sync"
	"time"

	"calculator_project/internal/config" // <-- Добавь этот импорт, если его нет
	localModels "calculator_project/internal/models"
	pb "calculator_project/internal/orchestrator/grpc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// isUUID проверяет, выглядит ли строка как UUID.
func isUUID(s string) bool {
	return uuidRegex.MatchString(s)
}

// GRPCServer представляет реализацию нашего gRPC сервиса CalculatorService.
// Он должен встраивать UnimplementedCalculatorServiceServer для обеспечения обратной совместимости.
type GRPCServer struct {
	pb.UnimplementedCalculatorServiceServer // Встраиваем сгенерированную заглушку

	DB     *sql.DB        // Соединение с базой данных
	Config *config.Config // <-- ДОБАВЛЯЕМ: Конфигурация сервиса Оркестратора
	// TODO: Добавить менеджер задач или другой компонент.
}

// NewGRPCServer создает новый экземпляр GRPCServer.
// Принимает необходимые зависимости: DB и Config.
func NewGRPCServer(db *sql.DB, cfg *config.Config) *GRPCServer { // <--- ИЗМЕНИ СИГНАТУРУ ФУНКЦИИ ТАК
	return &GRPCServer{
		UnimplementedCalculatorServiceServer: pb.UnimplementedCalculatorServiceServer{},
		DB:                                   db,
		Config:                               cfg, // <-- Сохраняем Config в структуре сервера
	}
}

// getOperationDuration: Вспомогательная функция (метод GRPCServer) для получения времени выполнения операции из конфигурации.
// Принимает строку с названием операции (напр., "+").
// Возвращает time.Duration, соответствующую времени выполнения этой операции согласно конфигурации.
func (s *GRPCServer) getOperationDuration(operation string) time.Duration { // <--- ДОБАВЬ ЭТУ ФУНКЦИЮ ЦЕЛИКОМ
	// <--- ДОБАВЛЕНО: Логирование входящей операции
	log.Printf("getOperationDuration: Получена операция='%s'", operation)

	// Используем значения времени из загруженной конфигурации Оркестратора (s.Config).
	// Значения в конфиге у нас в time.Duration (напр. 100 * time.Millisecond).
	// Возвращаем как time.Duration.
	switch operation {
	case "+":
		log.Println("getOperationDuration: Совпадение с '+', возвращаем", s.Config.TimeAdditionMs) // <--- ДОБАВЛЕНО: Логирование соответствия
		return s.Config.TimeAdditionMs
	case "-":
		log.Println("getOperationDuration: Совпадение с '-', возвращаем", s.Config.TimeSubtractionMs) // <--- ДОБАВЛЕНО: Логирование соответствия
		return s.Config.TimeSubtractionMs
	case "*":
		log.Println("getOperationDuration: Совпадение с '*', возвращаем", s.Config.TimeMultiplicationMs) // <--- ДОБАВЛЕНО: Логирование соответствия
		return s.Config.TimeMultiplicationMs
	case "/":
		log.Println("getOperationDuration: Совпадение с '/', возвращаем", s.Config.TimeDivisionMs) // <--- ДОБАВЛЕНО: Логирование соответствия
		return s.Config.TimeDivisionMs
	default:
		// Для неизвестных операций или операции "number" (она не требует вычислений)
		// возвращаем 0 задержку.
		log.Println("getOperationDuration: Нет совпадения для операции, возвращаем 0") // <--- ДОБАВЛЕНО: Логирование отсутствия соответствия
		return 0                                                                       // time.Duration(0)
	}
}

// GetTask: Реализация gRPC метода для получения задачи Агентом.
// Логика выбора готовой задачи перемещена в Go код после выборки Pending задач.
// Ищет первую готовую к выполнению задачу среди всех Pending задач и выдает ее.
// Агент вызывает этот метод, чтобы получить новую задачу для вычисления.
func (s *GRPCServer) GetTask(ctx context.Context, req *pb.TaskRequest) (*pb.TaskResponse, error) {
	log.Printf("Получен запрос GetTask от агента (ID: %s)", req.GetAgentId())

	// Находим готовую задачу в базе данных.
	// Задача готова, если она в статусе 'Pending' ИЛИ если все ее аргументы (если это Task ID)
	// имеют статус 'Completed'.
	// Используем транзакцию, чтобы безопасно выбрать ОДНУ задачу и сразу же пометить ее как взятую агентом (InProgress).
	// Этот подход уменьшает вероятность блокировок по сравнению с выборкой всех Pending задач и проверкой в Go.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}) // Начинаем транзакцию
	if err != nil {
		log.Printf("GetTask: Ошибка начала транзакции: %v", err)
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при начале транзакции")
	}
	defer tx.Rollback() // Гарантируем откат, если коммит не произойдет

	var readyTask localModels.CalculationTask // Переменная для хранения найденной задачиD
	// foundReadyTask := false                   // Флаг, указывающий, найдена ли готовая задача

	// SQL запрос для выборки ОДНОЙ готовой к выполнению задачи.
	// Задача готова, если:
	// 1. Ее статус 'Pending'.
	// 2. ИЛИ ее операция 'number' (Arg1 всегда числовой литерал).
	// 3. ИЛИ (для арифметических операций) оба ее аргумента являются числовыми литералами
	// 4. ИЛИ (для арифметических операций) оба ее аргумента являются Task ID,
	//    И задачи с этими ID имеют статус 'Completed'.
	// Для SQLite сложнее сделать такую проверку готовности прямо в SQL запросе SELECT LIMIT 1.
	// Более простой подход: выбрать ОДНУ задачу в статусе Pending И проверить ее готовность в Go.
	// Если она не готова, просто возвращаем "нет задач" для этого запроса GetTask.
	// Следующий запрос GetTask может выбрать следующую Pending задачу (или ту же, если ее не взяли), и т.д.

	// Оптимизированный SQL для выборки ОДНОЙ задачи в статусе Pending.
	// Мы выберем только статус Pending и проверим готовность позже в Go,
	// чтобы не усложнять SQL и не делать JOINы внутри критического GetTask запроса.
	selectOnePendingTaskSQL := `SELECT id, expression_id, operation, arg1, arg2, status FROM tasks WHERE status = ? LIMIT 1`

	err = tx.QueryRowContext(ctx, selectOnePendingTaskSQL, localModels.TaskStatusPending).Scan( // <--- Выбираем ОДНУ задачу
		&readyTask.ID,
		&readyTask.ExpressionID,
		&readyTask.Operation,
		&readyTask.Arg1,
		&readyTask.Arg2,
		&readyTask.Status, // Ожидаем 'Pending'
	)

	// Обрабатываем ошибки выборки.
	if err != nil {
		if err == sql.ErrNoRows {
			// Если задач в статусе Pending нет.
			log.Println("GetTask: Нет доступных (готовых) задач в статусе Pending.")
			// Откатываем транзакцию (defer сработает).
			return &pb.TaskResponse{NoTask: true}, nil // Говорим, что задач нет
		}
		// Если произошла другая ошибка выборки из базы данных.
		log.Printf("GetTask: Ошибка при выборке ОДНОЙ Pending задачи из БД: %v", err)
		// TODO: Возможно, тут стоит добавить логику повторных попыток для SQLITE_BUSY
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при выборке Pending задач из БД")
	}

	// Если задача в статусе Pending найдена.
	// Теперь ПРОВЕРЯЕМ ЕЕ ГОТОВНОСТЬ в Go коде.
	// Если она не готова, мы просто не выдаем ее в этом запросе GetTask.
	// Агент попробует снова позже.
	isArgReady := func(arg string, tx *sql.Tx) bool { // Функция для проверки готовности аргумента
		// Проверяем, является ли аргумент числовым литералом.
		if _, err := strconv.ParseFloat(arg, 64); err == nil {
			return true // Аргумент - числовой литерал
		}

		// Если не числовой литерал, возможно, это Task ID.
		// Проверяем статус зависимой задачи по ее ID.
		var status string
		err := tx.QueryRowContext(ctx, "SELECT status FROM tasks WHERE id = ?", arg).Scan(&status) // <--- Запрос ВНУТРИ ТРАНЗАКЦИИ!
		if err != nil {
			// Ошибка выборки или задача не найдена (не является Task ID).
			if err != sql.ErrNoRows {
				log.Printf("GetTask: Ошибка проверки статуса зависимой задачи %s: %v", arg, err)
			}
			return false // Не готов
		}
		// Задача найдена, проверяем ее статус.
		return status == localModels.TaskStatusCompleted // Аргумент готов, если зависимая задача Completed
	}

	isReady := false
	if readyTask.Operation == "number" {
		// Задача "number" всегда готова, если ее выбрали как Pending.
		isReady = true
	} else {
		// Арифметическая задача готова, если оба аргумента готовы.
		// Используем нашу вспомогательную функцию isArgReady.
		if isArgReady(readyTask.Arg1, tx) && isArgReady(readyTask.Arg2, tx) {
			isReady = true
		}
	}

	// Если найденная Pending задача оказалась НЕ готова к выполнению (ее зависимости еще не выполнены).
	if !isReady {
		log.Printf("GetTask: Найдена Pending задача %s, но она еще не готова (зависимости не выполнены). Не выдаем ее.", readyTask.ID)
		// Откатываем транзакцию (defer сработает).
		// Мы не нашли ГОТОВУЮ задачу для выдачи в этом запросе.
		return &pb.TaskResponse{NoTask: true, Task: nil}, nil
	}

	// Если мы дошли сюда, значит, найдена ОДНА Pending задача, и она ГОТОВА к выполнению.
	// Теперь нужно безопасно пометить ее как взятую (InProgress).
	updateTaskStatusSQL := `
		UPDATE tasks
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = ?` // Проверяем статус Pending перед обновлением для защиты от конкуренции

	// Выполняем обновление статуса ВНУТРИ ТРАНЗАКЦИИ.
	resultUpdate, err := tx.ExecContext(ctx, updateTaskStatusSQL, localModels.TaskStatusInProgress, readyTask.ID, localModels.TaskStatusPending) // <--- Обновляем статус
	if err != nil {
		log.Printf("GetTask: Ошибка при обновлении статуса найденной ГОТОВОЙ задачи %s на InProgress: %v", readyTask.ID, err)
		// Откатываем (defer сработает).
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при обновлении статуса найденной готовой задачи")
	}

	// Проверяем, что обновление затронуло ровно одну строку (дополнительная проверка на конкуренцию).
	rowsAffected, err := resultUpdate.RowsAffected()
	if err != nil {
		log.Printf("GetTask: Ошибка при получении RowsAffected после обновления статуса задачи %s: %v", readyTask.ID, err)
		// Логируем, но продолжаем, так как основное обновление, вероятно, прошло.
	} else if rowsAffected == 0 {
		// Это значит, что найденная ГОТОВАЯ задача с таким ID уже не в статусе Pending (ее взял другой агент в параллельном запросе GetTask).
		log.Printf("GetTask: Конкурентный доступ? Найденая ГОТОВАЯ задача %s уже не в статусе Pending при попытке обновить (RowsAffected = 0).", readyTask.ID)
		// Откатываем транзакцию (defer сработает).
		// Возвращаем "нет задач", так как не смогли атомарно захватить эту задачу.
		return &pb.TaskResponse{NoTask: true, Task: nil}, nil
	}

	// Если обновление статуса успешно, КОММИТИМ ТРАНЗАКЦИЮ.
	err = tx.Commit() // <--- КОММИТИМ!
	if err != nil {
		log.Printf("GetTask: Ошибка при коммите транзакции для задачи %s: %v", readyTask.ID, err)
		// Откатываем (defer сработает).
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при коммите транзакции")
	}

	// Если мы дошли сюда, транзакция успешна, задача найдена, ГОТОВА и помечена InProgress.
	// Теперь формируем protobuf ответ и возвращаем его агенту.

	pbTask := &pb.Task{
		Id:        readyTask.ID,
		Operation: readyTask.Operation,
		Arg1:      readyTask.Arg1, // Аргументы как есть (числа или Task ID)
		Arg2:      readyTask.Arg2, // Агент должен уметь парсить их в числа
		// Заполняем поле DurationMs из конфигурации.
		DurationMs: int64(s.getOperationDuration(readyTask.Operation) / time.Millisecond),
	}

	// Логируем выдачу задачи (используя данные из pbTask).
	log.Printf("GetTask: Выдана задача %s (Операция: %s, Args: %s, %s) агенту (ID: %s)",
		pbTask.Id, pbTask.Operation, pbTask.Arg1, pbTask.Arg2, req.GetAgentId())

	// Возвращаем успешный ответ с данными задачи.
	return &pb.TaskResponse{
		NoTask: false,  // Говорим, что есть задача
		Task:   pbTask, // Передаем структуру задачи
	}, nil // Ошибки gRPC нет
}

// Шаг 14.2: Улучшение логики SubmitResult для обработки зависимостей.
// После завершения задачи, зависимые задачи, которые ждали ее результата, должны
// стать "готовыми" и, возможно, перейти в статус Pending.

// SubmitResult: Реализация gRPC метода для отправки результата вычисления задачи Агентом.
// Улучшена логика обработки зависимостей: после завершения задачи, зависимые задачи
// обновляют свои аргументы и, если становятся готовыми, переводятся в статус Pending.
func (s *GRPCServer) SubmitResult(ctx context.Context, req *pb.ResultRequest) (*pb.ResultResponse, error) {
	log.Printf("Получен результат задачи %s: Result=%.6f, Success=%t, Error='%s'",
		req.GetTaskId(), req.GetResult(), req.GetSuccess(), req.GetErrorMessage())

	// 1. Проверяем, что TaskId не пустой.
	if req.GetTaskId() == "" {
		log.Println("SubmitResult: Получен запрос с пустым TaskId.")
		// Возвращаем ошибку InvalidArgument, так как входные данные неверны.
		return nil, status.Errorf(codes.InvalidArgument, "Task ID cannot be empty")
	}

	// Начинаем транзакцию. Важно, чтобы обновление задачи, зависимостей и выражения было атомарным.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("SubmitResult: Ошибка начала транзакции: %v", err)
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при начале обработки результата")
	}
	defer tx.Rollback() // Отложенная функция для отката транзакции в случае ошибки или паники.

	// Сначала получаем ExpressionID текущей задачи, это понадобится для поиска зависимостей и выражения.
	var expressionID string
	err = tx.QueryRowContext(ctx, "SELECT expression_id FROM tasks WHERE id = ?", req.GetTaskId()).Scan(&expressionID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("SubmitResult: Задача %s не найдена при получении ExpressionID.", req.GetTaskId())
			tx.Rollback() // Откатываем, так как задача не найдена.
			return nil, status.Errorf(codes.NotFound, "Task %s not found", req.GetTaskId())
		}
		log.Printf("SubmitResult: Ошибка при получении ExpressionID для задачи %s: %v", req.GetTaskId(), err)
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при получении ExpressionID")
	}
	log.Printf("SubmitResult: ExpressionID для задачи %s: %s", req.GetTaskId(), expressionID)

	// 2. Определяем новый статус задачи и готовим данные для обновления.
	var newStatus string
	var result sql.NullFloat64
	var errorMessage sql.NullString

	if req.GetSuccess() {
		newStatus = localModels.TaskStatusCompleted
		result = sql.NullFloat64{Float64: req.GetResult(), Valid: true} // Результат есть, Valid = true
		errorMessage = sql.NullString{String: "", Valid: false}         // Ошибки нет, Valid = false
		log.Printf("SubmitResult: Задача %s успешно завершена.", req.GetTaskId())
	} else {
		newStatus = localModels.TaskStatusFailed
		result = sql.NullFloat64{Float64: 0, Valid: false}                        // Результата нет, Valid = false
		errorMessage = sql.NullString{String: req.GetErrorMessage(), Valid: true} // Ошибка есть, Valid = true
		log.Printf("SubmitResult: Задача %s завершилась с ошибкой: %s", req.GetTaskId(), req.GetErrorMessage())

		// Если задача провалена, Expression тоже должен быть помечен как Failed сразу.
		// Мы сделаем это ниже при проверке статуса выражения.
	}

	// 3. Обновляем статус задачи, результат и сообщение об ошибке в базе данных.
	// Дополнительно проверяем, что текущий статус задачи InProgress.
	updateTaskSQL := `
		UPDATE tasks
		SET status = ?, result = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = ?`

	resultUpdate, err := tx.ExecContext(ctx, updateTaskSQL, newStatus, result, errorMessage, req.GetTaskId(), localModels.TaskStatusInProgress)
	if err != nil {
		log.Printf("SubmitResult: Ошибка обновления задачи %s в БД: %v", req.GetTaskId(), err)
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при обновлении задачи")
	}

	rowsAffected, err := resultUpdate.RowsAffected()
	if err != nil {
		log.Printf("SubmitResult: Ошибка при получении RowsAffected для задачи %s: %v", req.GetTaskId(), err)
	} else if rowsAffected == 0 {
		log.Printf("SubmitResult: Задача %s не найдена в статусе InProgress для обновления. Возможно, дублирующий результат или статус уже изменен.", req.GetTaskId())
		tx.Rollback()
		return nil, status.Errorf(codes.FailedPrecondition, "Task %s is not in InProgress status or not found", req.GetTaskId())
	}

	// 4. Если задача успешно завершена (Completed), обновляем аргументы зависимых задач и проверяем их готовность.
	if newStatus == localModels.TaskStatusCompleted {
		log.Printf("SubmitResult: Задача %s успешно выполнена, ищем зависимые задачи и проверяем их готовность.", req.GetTaskId())

		// SQL запрос для поиска зависимых задач В ТОМ ЖЕ ВЫРАЖЕНИИ.
		// Ищем задачи, у которых Arg1 ИЛИ Arg2 == req.GetTaskId() И чей статус еще не завершен.
		selectDependentTasksSQL := `
			SELECT id, operation, arg1, arg2, status
			FROM tasks
			WHERE expression_id = ? AND (arg1 = ? OR arg2 = ?)
			AND status != ? AND status != ?` // Ищем зависимые, которые еще не Completed/Failed

		// Выполняем запрос внутри транзакции.
		rows, err := tx.QueryContext(ctx, selectDependentTasksSQL,
			expressionID, // Используем ExpressionID, полученный ранее
			req.GetTaskId(), req.GetTaskId(),
			localModels.TaskStatusCompleted, localModels.TaskStatusFailed, // Исключаем уже завершенные
		)
		if err != nil {
			log.Printf("SubmitResult: Ошибка при поиске зависимых задач для %s: %v", req.GetTaskId(), err)
			// Логируем и продолжаем.
		} else {
			defer rows.Close()

			var tasksToUpdateStatus []localModels.CalculationTask // Список зависимых задач, которые могут стать Pending

			for rows.Next() {
				var dependentTask localModels.CalculationTask
				// Сканируем ID зависимой задачи, ее операцию, текущие аргументы и статус
				if err := rows.Scan(&dependentTask.ID, &dependentTask.Operation, &dependentTask.Arg1, &dependentTask.Arg2, &dependentTask.Status); err != nil {
					log.Printf("SubmitResult: Ошибка сканирования зависимой задачи: %v", err)
					continue
				}

				// Обновляем аргументы зависимой задачи В БАЗЕ ДАННЫХ, заменяя ссылку на выполненную задачу на ее результат.
				updateDependentArgSQL := `
					UPDATE tasks
					SET arg1 = CASE WHEN arg1 = ? THEN ? ELSE arg1 END,
						arg2 = CASE WHEN arg2 = ? THEN ? ELSE arg2 END,
                        updated_at = CURRENT_TIMESTAMP -- Обновляем updated_at при изменении аргумента
					WHERE id = ?`

				resultStr := fmt.Sprintf("%.6f", req.GetResult()) // Форматируем число в строку для сохранения в TEXT колонку

				_, err := tx.ExecContext(ctx, updateDependentArgSQL, req.GetTaskId(), resultStr, req.GetTaskId(), resultStr, dependentTask.ID)
				if err != nil {
					log.Printf("SubmitResult: Ошибка обновления аргументов зависимой задачи %s (зависит от %s): %v", dependentTask.ID, req.GetTaskId(), err)
					continue
				}
				log.Printf("SubmitResult: Обновлены аргументы зависимой задачи %s (зависела от %s) на результат: %s", dependentTask.ID, req.GetTaskId(), resultStr)

				// Обновляем аргументы в локальной структуре dependentTask для проверки готовности дальше
				if dependentTask.Arg1 == req.GetTaskId() {
					dependentTask.Arg1 = resultStr
				}
				if dependentTask.Arg2 == req.GetTaskId() {
					dependentTask.Arg2 = resultStr
				}

				// Добавляем эту зависимую задачу в список для потенциального обновления статуса.
				tasksToUpdateStatus = append(tasksToUpdateStatus, dependentTask)
			}
			if err := rows.Err(); err != nil {
				log.Printf("SubmitResult: Ошибка после обхода строк зависимых задач: %v", err)
			}

			// Теперь проверяем готовность зависимых задач из списка и обновляем их статус, если нужно.
			for _, depTask := range tasksToUpdateStatus {
				// Проверяем, стала ли зависимая задача готова к выполнению.
				// Задача готова, если ее статус еще не Pending/InProgress (он был другим, т.к. мы исключили Completed/Failed выше)
				// И ОБА ее аргумента теперь являются числами (после обновления ссылок на ID).

				// Функция для проверки, является ли строка числом
				isNumeric := func(s string) bool {
					if s == "" { // Пустая строка не число
						return false
					}
					_, err := strconv.ParseFloat(s, 64)
					return err == nil
				}

				// Задача готова, если она не завершена И (для "number" Arg1 число ИЛИ для других операций оба Arg числа)
				isReady := false
				if depTask.Operation == "number" {
					// Задача с операцией "number" зависит только от Arg1.
					// Готова, если Arg1 теперь число.
					isReady = isNumeric(depTask.Arg1)
				} else {
					// Арифметическая задача зависит от Arg1 и Arg2.
					// Готова, если Arg1 число И Arg2 число.
					isReady = isNumeric(depTask.Arg1) && isNumeric(depTask.Arg2)
				}

				// Если задача готова И ее текущий статус НЕ Pending/InProgress/Completed/Failed (т.е. она еще не активна)
				// тогда переводим ее в статус Pending.
				// (Ее статус должен был быть чем-то вроде "Blocked" или просто не "Pending" изначально).
				// В нашей текущей схеме статусов, если она не Completed/Failed/InProgress, она подразумевается как "Blocked"/'Pending_Blocked'.
				// Поэтому мы просто переводим ее в Pending, если она стала Ready и не в одном из активных/завершенных статусов.
				if isReady && depTask.Status != localModels.TaskStatusPending &&
					depTask.Status != localModels.TaskStatusInProgress &&
					depTask.Status != localModels.TaskStatusCompleted &&
					depTask.Status != localModels.TaskStatusFailed {

					// Если задача готова, обновляем ее статус на Pending.

					// Мы хотим обновить статус с ее ТЕКУЩЕГО статуса (который не Completed/Failed/InProgress)
					// на Pending, ТОЛЬКО если ее текущий статус не является одним из активных/завершенных.
					// Исходный статус зависимой задачи перед тем как она стала Ready, мог быть просто 'Pending' в БД,
					// но она не была готова, пока не получил результат зависимости.
					// Чтобы избежать лишних обновлений, лучше просто обновлять на Pending, если ее статус не активный/завершенный.
					// Проще: обновляем на Pending, если ее статус НЕ InProgress, Completed, Failed.
					updateStatusQuery := `
                         UPDATE tasks
                         SET status = ?, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ? AND status != ? AND status != ? AND status != ?`

					resultUpdateStatus, err := tx.ExecContext(ctx, updateStatusQuery,
						localModels.TaskStatusPending, depTask.ID,
						localModels.TaskStatusInProgress, localModels.TaskStatusCompleted, localModels.TaskStatusFailed)
					if err != nil {
						log.Printf("SubmitResult: Ошибка обновления статуса зависимой задачи %s на Pending: %v", depTask.ID, err)
					} else {
						rowsAffectedStatus, err := resultUpdateStatus.RowsAffected()
						if err != nil {
							log.Printf("SubmitResult: Ошибка получения RowsAffected при обновлении статуса зависимой задачи %s: %v", depTask.ID, err)
						} else if rowsAffectedStatus > 0 {
							log.Printf("SubmitResult: Зависимая задача %s стала готова и переведена в статус Pending.", depTask.ID)
						} else {
							log.Printf("SubmitResult: Зависимая задача %s стала готова, но ее статус уже не подходит для перевода в Pending.", depTask.ID)
						}
					}
				} // Конец if isReady
			} // Конец цикла по зависимым задачам для обновления статуса
		} // Конец if/else для rows, err при поиске зависимых задач
	} // Конец if newStatus == localModels.TaskStatusCompleted

	// 5. Проверка статуса всего выражения и обновление.
	// Находим общее количество задач и количество завершенных/проваленных для ExpressionID.
	checkExpressionStatusSQL := `
		SELECT
			COUNT(*) AS total_tasks,
			SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS completed_tasks,
			SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS failed_tasks
		FROM tasks
		WHERE expression_id = ?` // Используем ExpressionID, полученный ранее

	var totalTasks, completedTasks, failedTasks int
	err = tx.QueryRowContext(ctx, checkExpressionStatusSQL,
		localModels.TaskStatusCompleted, localModels.TaskStatusFailed,
		expressionID,
	).Scan(&totalTasks, &completedTasks, &failedTasks)

	if err != nil {
		log.Printf("SubmitResult: Ошибка при проверке статуса выражения %s: %v", expressionID, err)
		// Логируем, но продолжаем. Обновление статуса выражения не должно блокировать подтверждение результата задачи.
	} else {
		log.Printf("SubmitResult: Статус выражения %s (Total: %d, Completed: %d, Failed: %d)",
			expressionID, totalTasks, completedTasks, failedTasks)

		// Если все задачи выражения завершены (Completed или Failed).
		if totalTasks > 0 && (completedTasks+failedTasks) == totalTasks {
			var expressionStatusToUpdate string
			var finalResult sql.NullFloat64      // <--- Правильный тип для конечного результата выражения (число или NULL)
			var finalErrorMessage sql.NullString // Для сохранения ошибки выражения (текст или NULL)

			if failedTasks > 0 {
				// Если есть проваленные задачи, выражение провалено.
				expressionStatusToUpdate = localModels.ExpressionStatusFailed
				// Находим сообщение об ошибке из первой проваленной задачи для FinalResult выражения.
				var firstErrorMessage sql.NullString
				err := tx.QueryRowContext(ctx,
					`SELECT error_message FROM tasks WHERE expression_id = ? AND status = ? LIMIT 1`,
					expressionID, localModels.TaskStatusFailed).Scan(&firstErrorMessage)
				if err != nil && err != sql.ErrNoRows {
					log.Printf("SubmitResult: Ошибка при получении первого сообщения об ошибке для выражения %s: %v", expressionID, err)
					// Если не смогли получить первое сообщение, используем общее.
					finalErrorMessage = sql.NullString{String: fmt.Sprintf("Ошибка: %d задач провалено", failedTasks), Valid: true}
				} else {
					finalErrorMessage = firstErrorMessage // Используем первое найденное сообщение об ошибке
				}

				log.Printf("SubmitResult: Выражение %s завершено со статусом Failed.", expressionID)

				// Для проваленного выражения результат всегда NULL.
				finalResult = sql.NullFloat64{Valid: false} // Результат NULL для failed выражений

			} else {
				// Если все задачи успешно завершены.
				expressionStatusToUpdate = localModels.ExpressionStatusCompleted
				log.Printf("SubmitResult: Выражение %s завершено со статусом Completed. Получаем результат по RootTaskID.", expressionID)

				// --- ЛОГИКА ПОЛУЧЕНИЯ РЕЗУЛЬТАТА ПО ROOTTASKID ИДЕТ ЗДЕСЬ ---
				// Переменные finalResult и finalErrorMessage УЖЕ ОБЪЯВЛЕНЫ
				// в начале блока if totalTasks > 0 && (completedTasks+failedTasks) == totalTasks { ... }
				// Мы просто ПРИСВАИВАЕМ им значения здесь.

				// 1. Получаем RootTaskID для этого выражения.
				var rootTaskID sql.NullString
				err := tx.QueryRowContext(ctx, "SELECT root_task_id FROM expressions WHERE id = ?", expressionID).Scan(&rootTaskID)
				if err != nil {
					log.Printf("SubmitResult: Ошибка при получении root_task_id для выражения %s: %v", expressionID, err)
					finalResult = sql.NullFloat64{Valid: false} // Присваиваем значение ВНЕШНЕЙ finalResult
					// Логическая ошибка: expression завершено, но root_task_id не найден.
					// Возможно, статус Expression нужно изменить на Failed? Сейчас оставим Completed с NULL результатом.
				} else if !rootTaskID.Valid {
					// Если root_task_id NULL в БД. Это может произойти, если парсер не установил его,
					// или если выражение было просто числом (хотя для "2+3*4" он должен быть).
					log.Printf("SubmitResult: root_task_id для выражения %s равен NULL. Не удалось определить конечный результат по ID корневой задачи.", expressionID)
					finalResult = sql.NullFloat64{Valid: false} // Присваиваем значение ВНЕШНЕЙ finalResult
				} else {
					// root_task_id найден и валиден, получаем результат этой задачи.
					var taskResult sql.NullFloat64 // Временная переменная для результата задачи
					err := tx.QueryRowContext(ctx, "SELECT result FROM tasks WHERE id = ? AND expression_id = ?", rootTaskID.String, expressionID).Scan(&taskResult)
					if err != nil {
						log.Printf("SubmitResult: Ошибка при получении результата задачи %s (RootTaskID) для выражения %s: %v", rootTaskID.String, expressionID, err)
						finalResult = sql.NullFloat64{Valid: false} // Присваиваем значение ВНЕШНЕЙ finalResult
					} else if !taskResult.Valid {
						log.Printf("SubmitResult: Результат задачи %s (RootTaskID) для выражения %s равен NULL. Задача завершилась, но результат невалиден?", rootTaskID.String, expressionID)
						finalResult = sql.NullFloat64{Valid: false} // Присваиваем значение ВНЕШНЕЙ finalResult
					} else {
						// УСПЕШНО ПОЛУЧИЛИ РЕЗУЛЬТАТ КОРНЕВОЙ ЗАДАЧИ!
						finalResult = taskResult                                                                                                                        // Присваиваем результат задачи ВНЕШНЕЙ finalResult
						log.Printf("SubmitResult: Окончательный результат выражения %s (из RootTaskID %s): %.6f", expressionID, rootTaskID.String, finalResult.Float64) // Финальный лог результата
					}
				}

				// finalErrorMessage для успешно завершенного выражения устанавливается здесь
				// (Если ты не установил его в начале блока if totalTasks > 0..., сделай это там)
				// Или установи его здесь явно (так надежнее для этого случая):
				finalErrorMessage = sql.NullString{String: "", Valid: false} // Присваиваем значение ВНЕШНЕЙ finalErrorMessage
				// --- КОНЕЦ ЛОГИКИ ПОЛУЧЕНИЯ РЕЗУЛЬТАТА ПО ROOTTASKID ---

				// updateExpressionSQL и tx.ExecContext(...) идут дальше и используют finalResult/finalErrorMessage из внешней области
			} // Конец else (все успешно завершены)

			// --- UPDATE expressions query and execution MUST be inside this block ---
			// This 'finalResult' (sql.NullFloat64) and 'finalErrorMessage' (sql.NullString)
			// will be used in the UPDATE expressions query.

			// Update expression status and result/error in the expressions table.
			updateExpressionSQL := `
				UPDATE expressions
				SET status = ?, result = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ?`

			_, err = tx.ExecContext(ctx, updateExpressionSQL, expressionStatusToUpdate, finalResult, finalErrorMessage, expressionID)
			if err != nil {
				log.Printf("SubmitResult: Ошибка при обновлении статуса/результата/ошибки выражения %s: %v", expressionID, err)
				// Логируем ошибку обновления, но не обязательно возвращаем gRPC ошибку агенту на этом этапе.
				// Транзакция будет откатана через defer, если случилась более ранняя критическая ошибка.
				// Если обновление тут провалилось, состояние БД для выражения может быть некорректным.
				// В более надежной системе тут нужно решить, как обрабатывать (возможно, пометить выражение как проблемное).
			} else {
				log.Printf("SubmitResult: Статус выражения %s обновлен на '%s'.", expressionID, expressionStatusToUpdate)
			}
			// --- End of UPDATE expressions query and execution ---

		} else {
			// Expression is not yet completed (has tasks in Pending or InProgress status)
			log.Printf("SubmitResult: Expression %s is not yet completed (Total: %d, Completed: %d, Failed: %d).",
				expressionID, totalTasks, completedTasks, failedTasks)
			// Можно обновить статус выражения на InProgress, если он еще не такой.
			// TODO: Обновлять статус выражения на InProgress, если он был Pending.
		}
	} // Конец else для successful status check

	// 6. Если все обновления в транзакции прошли успешно, коммитим ее.
	err = tx.Commit()
	if err != nil {
		log.Printf("SubmitResult: Ошибка при коммите транзакции обработки результата для задачи %s: %v", req.GetTaskId(), err)
		// tx.Rollback() // Откат уже сделает defer
		return nil, status.Errorf(codes.Internal, "Ошибка сервера при коммите обработки результата")
	}

	log.Printf("SubmitResult: Результат задачи %s успешно обработан и сохранен.", req.GetTaskId())

	// 7. Возвращаем подтверждение Агенту.
	return &pb.ResultResponse{
		Received: true, // Подтверждаем получение и обработку результата
	}, nil // Ошибки gRPC нет
}
