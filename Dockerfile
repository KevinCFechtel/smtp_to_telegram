#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN go get -d -v ./...
RUN go build  -o /go/bin/app smtp_to_telegram.go

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN apk --no-cache add busybox-extras
COPY --from=builder /go/bin/app /app
ENTRYPOINT ["/bin/sh", "-c", "/app"]
LABEL Name=goRSSDedup Version=1.0