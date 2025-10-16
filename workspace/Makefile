# Build variables
RELEASE_DIR=./release
BIN_NAME=shakti
SRC=./src

# Deployment variables
PACKAGE_NAME=shakti
VERSION=$(shell cat version)
DEB_SKEL=./deb_skel
DEPLOY_BINPATH=${DEB_BASE}/opt/shakti

all: linux_amd64

linux_amd64: ARCH :=amd64
linux_amd64: DEB_BASE := ./$(PACKAGE_NAME)_$(VERSION)_$(ARCH)
linux_amd64:
	@echo "Building Shakti - Version: ${VERSION} Architecture: ${ARCH}"
	@echo "============================================"
	cd ${SRC} && go build -ldflags="-s -w" -o ${BIN_NAME} main.go
	mkdir -p ${RELEASE_DIR}
	mv ${SRC}/${BIN_NAME} ${RELEASE_DIR}/${BIN_NAME}
	upx --brute ${RELEASE_DIR}/${BIN_NAME}

	@echo "Building shakti debian"
	cp -r ${DEB_SKEL} ${DEB_BASE}
	sed -i 's/<VERSION>/${VERSION}/' ${DEB_BASE}/DEBIAN/control
	sed -i 's/<ARCH>/${ARCH}/' ${DEB_BASE}/DEBIAN/control
	cp ${RELEASE_DIR}/${BIN_NAME} ${DEPLOY_BINPATH}/${BIN_NAME}
	dpkg-deb --build ${DEB_BASE}

	@echo "Cleaning build files"
	rm -r ${DEB_BASE}
	@echo "Build complete"
	@echo "============================================";