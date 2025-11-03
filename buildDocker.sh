docker buildx create --name MultiBuilder --use
#docker buildx build --platform=linux/amd64,linux/arm64 -f "Dockerfile" -t kevincfechtel/gorssdedup:latest --push "." 
docker buildx build --platform=linux/amd64 -f "Dockerfile" -t kevincfechtel/smtp_to_telegram:latest --push "." 
docker buildx rm MultiBuilder