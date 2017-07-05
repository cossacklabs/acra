ifneq ($(BUILD_PATH),)
	BIN_PATH = $(BUILD_PATH)
else
	BIN_PATH = build
endif
#default engine
ifeq ($(PREFIX),)
PREFIX = /usr
endif
TEMP_GOPATH = temp_gopath
ABS_TEMP_GOPATH = $(shell pwd)/$(TEMP_GOPATH)

GIT_VERSION := $(shell if [ -d ".git" ]; then git version; fi 2>/dev/null)
ifdef GIT_VERSION
	VERSION = $(shell git describe --tags HEAD | cut -b 1-)
else
	VERSION = $(shell date -I)
endif

get_version:
	@echo $(VERSION)

DIST_FILENAME = $(VERSION).tar.gz

RSYNC_EXCLUDE = --exclude=$(TEMP_GOPATH) --exclude=$(BIN_PATH) --exclude=.acrakeys --exclude=.git --exclude=$(VERSION)

dist:
	@mkdir -p $(VERSION)
	@rsync -az $(RSYNC_EXCLUDE) ./* $(VERSION)
	@tar -zcf $(DIST_FILENAME) $(VERSION)
	@rm -rf $(VERSION)

temp_copy:
	@mkdir -p $(ABS_TEMP_GOPATH)/src/github.com/cossacklabs/acra
	@rsync -az $(RSYNC_EXCLUDE) ./* $(TEMP_GOPATH)/src/github.com/cossacklabs/acra
	@GOPATH=$(ABS_TEMP_GOPATH) go get github.com/cossacklabs/acra/cmd/...


build: temp_copy
	@mkdir -p $(BIN_PATH)
	@cp $(TEMP_GOPATH)/bin/* $(BIN_PATH)

clean:
	@rm -rf $(BIN_PATH)
	@rm -rf $(TEMP_GOPATH)


test_go:
	@GOPATH=$(ABS_TEMP_GOPATH) go test github.com/cossacklabs/acra/...

# should work postgresql on postgres:postgres@127.0.0.1:5432/postgres or override default connection params via TEST_DB_[HOST|PORT|USERNAME|USER_PASSWORD|NAME]
# and installed libpq-dev for python psycopg2
test_python:
	@virtualenv --python=python3 $(BIN_PATH)/test_env && \
		$(BIN_PATH)/test_env/bin/pip install -r tests/requirements.txt && \
		GOPATH=$(ABS_TEMP_GOPATH) $(BIN_PATH)/test_env/bin/python $(ABS_TEMP_GOPATH)/src/github.com/cossacklabs/acra/tests/test.py

test: temp_copy test_go test_python
	
COSSACKLABS_URL = https://www.cossacklabs.com
# tag version from VCS
LICENSE_NAME = "Apache License Version 2.0"
MAINTAINER = "CossackLabs LTD <dev@cossacklabs.com>"
DEBIAN_DEPENDENCIES = 'libssl-dev libthemis'
DEBIAN_ARCHITECTURE = `dpkg --print-architecture`
DEBIAN_DESCRIPTION = "Acra helps you easily secure your databases in distributed, microservice-rich environments. \
	It allows you to selectively encrypt sensitive records with strong multi-layer cryptography, detect potential \
	intrusions and SQL injections and cryptographically compartmentalize data stored in large sharded schemes. \
	Acra's security model guarantees that if your database or your application become compromised, they will not \
	leak sensitive data, or keys to decrypt them."

unpack_dist:
	@tar -xf $(DIST_FILENAME)

deb: build
	@mkdir -p '$(BIN_PATH)/deb'

	@fpm --input-type dir \
		 --output-type deb \
		 --name acra \
		 --license $(LICENSE_NAME) \
		 --url '$(COSSACKLABS_URL)' \
		 --description $(DEBIAN_DESCRIPTION) \
		 --maintainer $(MAINTAINER) \
		 --package $(BIN_PATH)/deb/ \
		 --architecture $(DEBIAN_ARCHITECTURE) \
		 --version $(VERSION) \
		 --deb-build-depends $(DEBIAN_DEPENDENCIES) \
		 --deb-priority optional \
		 --category security \
		 $(TEMP_GOPATH)/bin/=$(PREFIX)/bin/acra 1>/dev/null

# it's just for printing .deb files
	@find $(BIN_PATH) -name \*.deb


rpm: build
	@mkdir -p $(BIN_PATH)/rpm

	@fpm --input-type dir \
    		 --output-type rpm \
    		 --name acra \
    		 --license $(LICENSE_NAME) \
    		 --url '$(COSSACKLABS_URL)' \
    		 --description $(DEBIAN_DESCRIPTION) \
    		 --maintainer $(MAINTAINER) \
    		 --package $(BIN_PATH)/rpm/ \
    		 --version $(VERSION) \
    		 --category security \
    		 $(TEMP_GOPATH)/bin/=$(PREFIX)/bin/acra 1>/dev/null
# it's just for printing .deb files
	@find $(BIN_PATH) -name \*.rpm