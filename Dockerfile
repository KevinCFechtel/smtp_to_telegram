#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN go get -d -v ./...
RUN go build  -o /go/bin/app smtp_to_telegram.go

#final stage
FROM alpine:latest
ENV CONFIG_FILE_PATH='NoConfigFile'
ENV SMTP_LISTEN='127.0.0.1:2525'
ENV TELEGRAM_CHAT_IDS=''
ENV TELEGRAM_BOT_TOKEN=''
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/app /app
ENTRYPOINT ["/bin/sh", "-c", "/app --configFilePath=${CONFIG_FILE_PATH} --smtpListen=${SMTP_LISTEN} --telegramChatIds=${TELEGRAM_CHAT_IDS} --telegramBotToken=${TELEGRAM_BOT_TOKEN}"]
LABEL Name=goRSSDedup Version=1.0