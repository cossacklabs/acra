ifneq ($(BUILD_PATH),)
    BIN_PATH = $(BUILD_PATH)
else
    BIN_PATH = build
endif

ifeq ($(PREFIX),)
    PREFIX = /usr
endif

TEMP_GOPATH = temp_gopath
ABS_TEMP_GOPATH := $(shell pwd)/$(TEMP_GOPATH)

ifneq ($(GIT_BRANCH),)
    BRANCH = $(GIT_BRANCH)
else
    BRANCH = master
endif

GIT_VERSION := $(shell if [ -d ".git" ]; then git version; fi 2>/dev/null)
ifdef GIT_VERSION
    VERSION = $(shell git describe --tags HEAD | cut -b 1-)
    GIT_HASH = $(shell git rev-parse --verify HEAD)
else
    VERSION = $(shell date -I)
endif

.PHONY: get_version dist temp_copy install clean test_go test_python test \
        test_all unpack_dist deb rpm docker docker_push

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

install: temp_copy
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

# alias for unification with other products
test_all: test

PACKAGE_NAME = acra
COSSACKLABS_URL = https://www.cossacklabs.com
MAINTAINER = "Cossack Labs Limited <dev@cossacklabs.com>"

# tag version from VCS
LICENSE_NAME = "Apache License Version 2.0"

DEBIAN_CODENAME := $(shell lsb_release -cs 2> /dev/null)
DEBIAN_ARCHITECTURE = `dpkg --print-architecture 2>/dev/null`
DEBIAN_DEPENDENCIES = --depends openssl --depends libthemis
RPM_DEPENDENCIES = --depends openssl --depends libthemis

ifeq ($(shell lsb_release -is 2> /dev/null),Debian)
    NAME_SUFFIX = $(VERSION)+$(DEBIAN_CODENAME)_$(DEBIAN_ARCHITECTURE).deb
    OS_CODENAME = $(shell lsb_release -cs)
else ifeq ($(shell lsb_release -is 2> /dev/null),Ubuntu)
    NAME_SUFFIX = $(VERSION)+$(DEBIAN_CODENAME)_$(DEBIAN_ARCHITECTURE).deb
    OS_CODENAME = $(shell lsb_release -cs)
else
    OS_NAME = $(shell cat /etc/os-release | grep -e "^ID=\".*\"" | cut -d'"' -f2)
    OS_VERSION = $(shell cat /etc/os-release | grep -i version_id|cut -d'"' -f2)
    ARCHITECTURE = $(shell arch)
    RPM_VERSION = $(shell echo -n "$(VERSION)"|sed s/-/_/g)
    NAME_SUFFIX = $(RPM_VERSION).$(OS_NAME)$(OS_VERSION).$(ARCHITECTURE).rpm
endif

SHORT_DESCRIPTION = "Acra helps you easily secure your databases in distributed, microservice-rich environments"
RPM_SUMMARY = "Acra helps you easily secure your databases in distributed, microservice-rich environments. \
    It allows you to selectively encrypt sensitive records with strong multi-layer cryptography, detect potential \
    intrusions and SQL injections and cryptographically compartmentalize data stored in large sharded schemes. \
    Acra's security model guarantees that if your database or your application become compromised, they will not \
    leak sensitive data, or keys to decrypt them."

BUILD_DATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

unpack_dist:
	@tar -xf $(DIST_FILENAME)

deb: install
	@mkdir -p '$(BIN_PATH)/deb'
	@fpm --input-type dir \
		 --output-type deb \
		 --name $(PACKAGE_NAME) \
		 --license $(LICENSE_NAME) \
		 --url '$(COSSACKLABS_URL)' \
		 --description $(SHORT_DESCRIPTION) \
		 --maintainer $(MAINTAINER) \
		 --package $(BIN_PATH)/deb/$(PACKAGE_NAME)_$(NAME_SUFFIX) \
		 --architecture $(DEBIAN_ARCHITECTURE) \
		 --version $(VERSION)+$(OS_CODENAME) \
		 $(DEBIAN_DEPENDENCIES) \
		 --deb-priority optional \
		 --category security \
		 $(TEMP_GOPATH)/bin/=$(PREFIX)/bin
# it's just for printing .deb files
	@find $(BIN_PATH) -name \*.deb

rpm: install
	@mkdir -p $(BIN_PATH)/rpm
	@fpm --input-type dir \
		--output-type rpm \
		--name $(PACKAGE_NAME) \
		--license $(LICENSE_NAME) \
		--url '$(COSSACKLABS_URL)' \
		--description $(SHORT_DESCRIPTION) \
		--rpm-summary $(RPM_SUMMARY) \
		--maintainer $(MAINTAINER) \
		$(RPM_DEPENDENCIES) \
		--package $(BIN_PATH)/rpm/$(PACKAGE_NAME)-$(NAME_SUFFIX) \
		--version $(RPM_VERSION) \
		--category security \
		$(TEMP_GOPATH)/bin/=$(PREFIX)/bin
# it's just for printing .rpm files
	@find $(BIN_PATH) -name \*.rpm

define docker_build
	@docker image build \
		--no-cache=true \
		--build-arg VERSION=$(VERSION)\
		--build-arg VCS_URL="https://github.com/cossacklabs/acra" \
		--build-arg VCS_REF=$(GIT_HASH) \
		--build-arg VCS_BRANCH=$(BRANCH) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag cossacklabs/$(1):$(GIT_HASH) \
		-f ./docker/$(1).dockerfile \
		.
	for tag in $(2); do \
		docker tag cossacklabs/$(1):$(GIT_HASH) cossacklabs/$(1):$$tag; \
	done
endef

ifeq ($(BRANCH),stable)
    CONTAINER_TAGS = stable latest $(VERSION)
else ifeq ($(BRANCH),master)
    CONTAINER_TAGS = master current $(VERSION)
endif

docker:
	$(call docker_build,acra-build,)
	$(call docker_build,acraserver,$(CONTAINER_TAGS))
	$(call docker_build,acraproxy,$(CONTAINER_TAGS))
	$(call docker_build,acra_genkeys,$(CONTAINER_TAGS))
	@docker image rm cossacklabs/acra-build:$(GIT_HASH)

docker_push: docker
	@docker push cossacklabs/acraserver
	@docker push cossacklabs/acraproxy
	@docker push cossacklabs/acra_genkeys
