rm deploy/smtp_to_telegram
GOOS=linux GOARCH=amd64 go build -o deploy/smtp_to_telegram smtp_to_telegram.go