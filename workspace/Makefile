# Build variables
RELEASE_DIR=./release
BIN_NAME=shakti
SRC=./src

# Deployment variables
PACKAGE_NAME=shakti
ARCH=amd64
VERSION=1.0.0
DEB_SKEL=./deb_skel

DEB_BASE=./${PACKAGE_NAME}_${VERSION}_${ARCH}.deb
DEPLOY_BINPATH=${DEB_BASE}/opt/shakti

all: build deploy clean

build:
	cd ${SRC} && go build -ldflags="-s -w" -o ${BIN_NAME} main.go
	mkdir -p ${RELEASE_DIR}
	mv ${SRC}/${BIN_NAME} ${RELEASE_DIR}/${BIN_NAME}
	upx --brute ${RELEASE_DIR}/${BIN_NAME}

deploy:
	cp -r ${DEB_SKEL} ${DEB_BASE}
	cp ${RELEASE_DIR}/${BIN_NAME} ${DEPLOY_BINPATH}/${BIN_NAME}
	dpkg-deb --build ${DEB_BASE}

clean:
	rm -r ${DEB_BASE}