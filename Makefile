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
RSYNC_COPY = acrawriter cmd docker examples io LICENSE poison tests utils zone benchmarks circle.yml configs decryptor fuzz keystore Makefile README.md wrappers

dist:
	@mkdir -p $(VERSION)
	@rsync -az $(RSYNC_EXCLUDE) $(RSYNC_COPY) $(VERSION)
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

test: temp_copy test_go
	
COSSACKLABS_URL = https://www.cossacklabs.com
MAINTAINER = "Cossack Labs Limited <dev@cossacklabs.com>"

# tag version from VCS
LICENSE_NAME = "Apache License Version 2.0"

DEBIAN_VERSION := $(shell cat /etc/debian_version 2> /dev/null)
DEBIAN_STRETCH_VERSION := libssl1.0.2
DEBIAN_ARCHITECTURE = `dpkg --print-architecture 2>/dev/null`
# 9.0 == stretch
# if found 9. (9.1, 9.2, ...) then it's debian 9.x
ifeq ($(findstring 9.,$(DEBIAN_VERSION)),9.)
        DEBIAN_DEPENDENCIES := '$(DEBIAN_STRETCH_VERSION) libthemis'
else ifeq ($(DEBIAN_VERSION),stretch/sid)
        DEBIAN_DEPENDENCIES := '$(DEBIAN_STRETCH_VERSION) libthemis'
else
        DEBIAN_DEPENDENCIES := 'openssl libthemis'
endif
RPM_DEPENDENCIES = 'openssl libthemis'

ifeq ($(shell lsb_release -is 2> /dev/null),Debian)
#0.9.4-153-g9915004+jessie_amd64.deb.
	NAME_SUFFIX = $(VERSION)+$(shell lsb_release -cs)_$(DEBIAN_ARCHITECTURE).deb
else ifeq ($(shell lsb_release -is 2> /dev/null),Ubuntu)
	NAME_SUFFIX = $(VERSION)+$(shell lsb_release -cs)_$(DEBIAN_ARCHITECTURE).deb
else
	OS_NAME = $(shell cat /etc/os-release | grep -e "^ID=\".*\"" | cut -d'"' -f2)
	OS_VERSION = $(shell cat /etc/os-release | grep -i version_id|cut -d'"' -f2)
	ARCHITECTURE = $(shell arch)
	NAME_SUFFIX = $(VERSION).$(OS_NAME)$(OS_VERSION).$(ARCHITECTURE).rpm
endif

SHORT_DESCRIPTION = "Acra helps you easily secure your databases in distributed, microservice-rich environments"
RPM_SUMMARY = "Acra helps you easily secure your databases in distributed, microservice-rich environments. \
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
		 --description $(SHORT_DESCRIPTION) \
		 --maintainer $(MAINTAINER) \
		 --package $(BIN_PATH)/deb/acra_$(NAME_SUFFIX) \
		 --architecture $(DEBIAN_ARCHITECTURE) \
		 --version $(VERSION) \
		 --depends $(DEBIAN_DEPENDENCIES) \
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
		--description $(SHORT_DESCRIPTION) \
		--rpm-summary $(RPM_SUMMARY) \
		--maintainer $(MAINTAINER) \
		--depends $(RPM_DEPENDENCIES) \
		--package $(BIN_PATH)/rpm/acra_$(NAME_SUFFIX) \
		--version $(VERSION) \
		--category security \
		$(TEMP_GOPATH)/bin/=$(PREFIX)/bin/acra 1>/dev/null
# it's just for printing .rpm files
	@find $(BIN_PATH) -name \*.rpm
