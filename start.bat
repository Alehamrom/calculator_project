@echo off
setlocal
cd /d "%~dp0"

echo [Gocalc] Запуск локального режима...

:: Настраиваем переменные окружения для локального запуска
set DATABASE_FILE=calculator.db
set HTTP_LISTEN_ADDR=:8080
set GRPC_LISTEN_ADDR=:50051
set ORCHESTRATOR_GRPC_ADDRESS=localhost:50051
set JWT_SECRET=super_secret_local_key

echo [Gocalc] Запуск Оркестратора...
start "Gocalc: Orchestrator" cmd /k "go run ./cmd/calc_service"

echo [Gocalc] Ожидание 3 секунды для старта gRPC сервера...
timeout /t 3 /nobreak >nul

echo [Gocalc] Запуск Агента...
start "Gocalc: Agent" cmd /k "go run ./cmd/agent"

echo [Gocalc] Сервисы запущены! Оркестратор открыт на http://localhost:8080
echo Закройте консольные окна, чтобы остановить сервисы.
endlocal
