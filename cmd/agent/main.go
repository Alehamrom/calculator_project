package main

import (
	agent "calculator_project/internal/agent"
	pb "calculator_project/internal/orchestrator/grpc"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config: Структура для хранения конфигурации сервиса Агента.
// Здесь мы определяем, какие настройки нужны Агенту при запуске.
type Config struct {
	OrchestratorGRPCAddr string // Адрес gRPC сервера Оркестратора (например, "localhost:50051")
	AgentID              string // Уникальный идентификатор этого Агента. Может понадобиться Оркестратору.
}

// loadConfig: Читает конфигурацию Агента из переменных среды.
// Если переменная среды не задана, используется значение по умолчанию.
func loadConfig() (*Config, error) {
	cfg := &Config{
		// Значения по умолчанию для настроек Агента
		OrchestratorGRPCAddr: "localhost:50051",  // Адрес Оркестратора по умолчанию
		AgentID:              "agent-default-id", // Простой ID агента по умолчанию
	}

	// Чтение адреса gRPC сервера Оркестратора из переменной среды ORCHESTRATOR_GRPC_ADDRESS
	orchAddr := os.Getenv("ORCHESTRATOR_GRPC_ADDRESS") // Получаем значение
	log.Printf("Debug: ORCHESTRATOR_GRPC_ADDRESS raw env value: '%s'", orchAddr)
	if orchAddr != "" {
		cfg.OrchestratorGRPCAddr = orchAddr
	}

	// Чтение ID Агента из переменной среды AGENT_ID
	agentID := os.Getenv("AGENT_ID") // Получаем значение
	log.Printf("Debug: AGENT_ID raw env value: '%s'", agentID)
	if agentID != "" {
		cfg.AgentID = agentID
	}

	log.Printf("Конфигурация Агента загружена: %+v", cfg) // Логируем загруженную конфигурацию
	return cfg, nil
}

func main() {
	log.Println("Запуск сервиса Агента...")

	// 1. Загружаем конфигурацию для Агента.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Ошибка при загрузке конфигурации Агента: %v", err) // Если конфигурация не загрузилась, останавливаемся
	}

	// 2. Устанавливаем соединение с gRPC сервером Оркестратора.
	log.Printf("Попытка подключения к gRPC серверу Оркестратора на %s...", cfg.OrchestratorGRPCAddr)

	// Создаем контекст с таймаутом для попытки подключения.
	// Если за 5 секунд не удалось подключиться, попытка прервется.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Гарантируем вызов cancel() для освобождения ресурсов контекста

	// DialContext устанавливает соединение.
	// grpc.WithTransportCredentials(insecure.NewCredentials()) указывает использовать нешифрованное соединение.
	conn, err := grpc.DialContext(ctx, cfg.OrchestratorGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Не удалось подключиться к gRPC серверу Оркестратора (%s): %v", cfg.OrchestratorGRPCAddr, err) // Если не подключились, останавливаемся
	}
	// Отложенное закрытие gRPC соединения, когда функция main завершится.
	defer conn.Close()

	log.Printf("Успешно подключено к gRPC серверу Оркестратора на %s", cfg.OrchestratorGRPCAddr)

	// 3. Создаем gRPC клиента для нашего CalculatorService.
	// Используем сгенерированную нами ранее функцию NewCalculatorServiceClient, передавая ей установленное соединение.
	calculatorClient := pb.NewCalculatorServiceClient(conn)

	log.Println("Клиент CalculatorService gRPC создан. Агент готов к работе.")

	log.Println("Агент запускает цикл обработки задач.")

	for { // Бесконечный цикл. Агент будет работать до принудительной остановки.
		func() {
			// Создаем контекст с таймаутом для gRPC вызова GetTask.
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second) // Таймаут 1 секунда на запрос задачи
			// defer cancel() вызовется, когда эта анонимная функция (представляющая одну итерацию) завершится.
			defer cancel() // Это исправляет предупреждение и утечку ресурсов!

			// 1. Запрашиваем новую задачу у Оркестратора.
			// Передаем контекст и TaskRequest с ID агента.
			taskResp, err := calculatorClient.GetTask(ctx, &pb.TaskRequest{AgentId: cfg.AgentID})
			if err != nil {
				// Если произошла ошибка при вызове GetTask (например, Оркестратор недоступен, ошибка сети).
				log.Printf("Ошибка при запросе задачи у Оркестратора: %v. Повторная попытка через 5 секунд.", err)
				// Не вызываем cancel() здесь явно, т.к. defer сделает это при выходе из анонимной функции (через return ниже).
				time.Sleep(5 * time.Second) // Делаем паузу перед следующей попыткой запроса задачи
				return                      // Выходим из анонимной функции, чтобы перейти к следующей итерации внешнего цикла
			}

			// 2. Обрабатываем ответ от Оркестратора.
			if taskResp.GetNoTask() {
				// Оркестратор сообщил, что задач пока нет.
				log.Println("Нет доступных задач. Повторная попытка через 2 секунды.")
				// Не вызываем cancel() здесь явно.
				time.Sleep(2 * time.Second) // Ждем 2 секунды перед повторным запросом
				return                      // Выходим из анонимной функции
			}

			// Если мы здесь, значит, Оркестратор прислал задачу (NoTask == false).
			task := taskResp.GetTask() // Получаем саму структуру задачи из ответа
			if task == nil {
				// Это неожиданная ситуация: NoTask == false, но Task == nil. Ошибка в логике Оркестратора?
				log.Println("Получен ответ с NoTask=false, но Task=nil. Пропускаем и ждем.")
				time.Sleep(2 * time.Second)
				return // Выходим из анонимной функции
			}
			// Логируем все поля задачи, включая новую длительность из protobuf.
			log.Printf("Получена задача %s: Операция='%s', Аргументы='%s', '%s', Длительность=%dms",
				task.GetId(), task.GetOperation(), task.GetArg1(), task.GetArg2(), task.GetDurationMs())

			durationMs := task.GetDurationMs()
			if durationMs > 0 {
				duration := time.Duration(durationMs) * time.Millisecond
				log.Printf("Задача %s: Имитация выполнения операции, пауза %dms...", task.GetId(), durationMs)
				time.Sleep(duration)
				log.Printf("Задача %s: Пауза %dms завершена.", task.GetId(), durationMs)
			} else {
				log.Printf("Задача %s: Длительность 0ms, без паузы.", task.GetId())
			}

			var result float64 = 0.0     // Переменная для хранения числового результата вычисления. Инициализируем 0.0.
			var success bool = true      // Флаг успешности вычисления. Инициализируем true.
			var errorMessage string = "" // Строка для сообщения об ошибке. Инициализируем пустой строкой.

			// Переменные для хранения аргументов после парсинга в float64 и для ошибки вычисления.
			// Объявляем их здесь, чтобы они были доступны для проверки ошибки и отправки результата.
			var arg1Float, arg2Float float64
			var calcErr error // Переменная для ошибки, которую вернет CalculateOperation

			// Сначала обрабатываем специальный случай операции "number".
			// Эта операция означает, что Arg1 сам является числовым результатом задачи.
			if task.GetOperation() == "number" {
				// Для операции "number" парсим Arg1 напрямую как окончательный результат. Arg2 игнорируется.
				// Используем оператор присваивания (=), т.к. переменная result уже объявлена выше с помощью var.
				result, calcErr = strconv.ParseFloat(task.GetArg1(), 64)

				if calcErr != nil {
					// Если Arg1 не парсится в число для операции "number", это ошибка выполнения задачи.
					success = false // Вычисление неуспешно из-за ошибки парсинга
					// Формируем сообщение об ошибке парсинга Arg1.
					errorMessage = fmt.Sprintf("Ошибка парсинга числа для операции 'number': Arg1='%s' (%v)", task.GetArg1(), calcErr)
					log.Printf("Задача %s: Ошибка парсинга числа (операция 'number') - %s", task.GetId(), errorMessage)
					// В этом случае result сохранит значение по умолчанию 0.0 или будет NaN, возвращенный ParseFloat.
				}
				// Если calcErr равен nil, значит, Arg1 успешно спарсился в число.
				// success останется true, errorMessage останется "". result будет содержать спарсенное число.

			} else { // Обрабатываем стандартные бинарные операции (+, -, *, /)

				// Для бинарных операций сначала парсим оба аргумента из строк в float64.
				// Объявляем локальные переменные ошибок парсинга здесь с помощью :=,
				// т.к. они нужны только в этом блоке if/else.
				var err1, err2 error
				// Используем оператор присваивания (=), т.к. arg1Float и arg2Float уже объявлены выше с помощью var.
				arg1Float, err1 = strconv.ParseFloat(task.GetArg1(), 64)
				arg2Float, err2 = strconv.ParseFloat(task.GetArg2(), 64)

				// Проверяем ошибки парсинга аргументов для бинарных операций.
				if err1 != nil || err2 != nil {
					// Если парсинг любого из аргументов провалился, это ошибка выполнения задачи ДО самой операции.
					success = false // Парсинг аргументов неуспешен
					// Формируем сообщение об ошибке парсинга аргументов.
					errorMessage = fmt.Sprintf("Ошибка парсинга аргументов для операции '%s': Arg1='%s' (%v), Arg2='%s' (%v)",
						task.GetOperation(), task.GetArg1(), err1, task.GetArg2(), err2)
					log.Printf("Задача %s: Ошибка парсинга аргументов - %s", task.GetId(), errorMessage)
					// В этом случае мы НЕ вызываем функцию agent.CalculateOperation. calcErr останется nil.

				} else {
					// Аргументы успешно спарсены в float64. Теперь вызываем вынесенную функцию для выполнения самой бинарной операции.
					// Используем оператор присваивания (=) для result и calcErr, т.к. они объявлены выше.
					// result получит числовой результат операции, calcErr получит ошибку (например, "деление на ноль") или nil.
					result, calcErr = agent.CalculateOperation(arg1Float, arg2Float, task.GetOperation()) // <-- Вызов новой функции

					// Проверяем ошибку, возвращенную функцией CalculateOperation.
					if calcErr != nil {
						// Если CalculateOperation вернула ошибку (например, деление на ноль, неизвестная операция),
						// это ошибка выполнения задачи.
						success = false                // Вычисление неуспешно из-за ошибки в самой операции
						errorMessage = calcErr.Error() // Сообщение об ошибке берем из ошибки, возвращенной CalculateOperation
						log.Printf("Задача %s: Ошибка вычисления - %s", task.GetId(), errorMessage)
						// result в этом случае будет 0.0 (как возвращает CalculateOperation при ошибке).
					}
					// Если calcErr равен nil, значит, CalculateOperation выполнилась без внутренней ошибки.
					// success останется true, errorMessage останется "". result будет содержать вычисленное значение.
				}
			}

			// --- Конец обработки разных типов задач/операций ---

			// Логируем финальный результат вычисления или факт ошибки, используя переменные result, success, errorMessage,
			// которые были объявлены в начале этой анонимной функции и доступны здесь.
			if success {
				log.Printf("Задача %s: Вычисление завершено. Результат = %.6f", task.GetId(), result)
			} else {
				log.Printf("Задача %s: Вычисление завершено с ошибкой: %s", task.GetId(), errorMessage)
			}

			// *** Логика отправки результата обратно Оркестратору ***
			// Формируем gRPC запрос SubmitResultRequest, используя финальные значения result, success, errorMessage.
			resultReq := &pb.ResultRequest{
				TaskId:       task.GetId(), // ID задачи
				Result:       result,       // Числовой результат (0.0 или NaN при ошибке, как возвращает CalculateOperation)
				Success:      success,      // Финальный статус успешности
				ErrorMessage: errorMessage, // Финальное сообщение об ошибке (пустая строка, если success == true)
			}

			// Создаем контекст с таймаутом для вызова SubmitResult.
			// Если Оркестратор не отвечает или завален запросами, вызов SubmitResult не будет висеть вечно.
			submitCtx, submitCancel := context.WithTimeout(context.Background(), 5*time.Second) // Таймаут 5 секунд на отправку результата
			defer submitCancel()                                                                // Гарантируем отмену контекста отправки после завершения SubmitResult или его отмены

			// Вызываем метод SubmitResult у gRPC клиента для отправки результата.
			submitResp, err := calculatorClient.SubmitResult(submitCtx, resultReq)

			// Обрабатываем ответ и ошибки при отправке результата.
			if err != nil {
				// Если произошла ошибка связи с Оркестратором при отправке результата.
				log.Printf("Ошибка при отправке результата задачи %s Оркестратору: %v. Результат может быть не обработан Оркестратором.", task.GetId(), err)
				// если Оркестратор был временно недоступен.
			} else if submitResp == nil {
				// Если ответ от Оркестратора пришел nil (неожиданно).
				log.Printf("Получен пустой ответ от Оркестратора при отправке результата задачи %s.", task.GetId())
			} else if !submitResp.GetReceived() {
				// Оркестратор ответил, но сообщил, что не смог принять результат (Received = false).
				log.Printf("Оркестратор не подтвердил прием результата для задачи %s.", task.GetId())
			} else {
				// Результат успешно отправлен и подтвержден Оркестратором.
				log.Printf("Результат задачи %s успешно отправлен и подтвержден Оркестратором.", task.GetId())
			}

			// После обработки задачи (вычисления и отправки результата) анонимная функция завершается,
			// defer cancel() для контекста GetTask вызывается.
			// Затем внешний цикл for {} переходит к следующей итерации.

			// Небольшая пауза после полной обработки задачи, если нужно, перед следующим запросом GetTask.
			time.Sleep(500 * time.Millisecond) // Пример паузы (убрать или сделать настраиваемой)

		}() // Сразу вызываем эту анонимную функцию для выполнения одной итерации
		// Внешний цикл for {} продолжает работу, начиная новую итерацию.

	}

	// Код здесь никогда не выполнится, так как цикл 'for {}' бесконечный.
}
