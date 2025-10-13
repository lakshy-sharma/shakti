RELEASE_DIR=./release

all:
	go build -ldflags="-s -w" -o ${RELEASE_DIR}/shakti main.go
	upx --brute ${RELEASE_DIR}/shakti
