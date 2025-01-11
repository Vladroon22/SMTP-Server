# Используем официальный образ Go для сборки
FROM golang:1.23.4-alpine AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы проекта
COPY . .

# Скачиваем зависимости
RUN go mod download

# Собираем приложение
RUN go build -o smtp-server ./cmd/main.go

# Используем минимальный образ для запуска
FROM alpine:latest

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем собранный бинарник из builder
COPY --from=builder /app/smtp-server .
COPY private_key.pem /app/private_key.pem

# Открываем порт для SMTP
EXPOSE 2525

# Запускаем приложение
CMD ["./smtp-server"]