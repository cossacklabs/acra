#===== Variables ===============================================================

#----- Application -------------------------------------------------------------

APP_NAME := acra
APP_LICENSE_NAME = Apache License Version 2.0

VCS_URL := https://github.com/cossacklabs/acra

APP_SHORT_DESCRIPTION := "Acra helps you easily secure your databases in distributed, microservice-rich environments"
APP_LONG_DESCRIPTION := "Acra helps you easily secure your databases in distributed, microservice-rich environments. \
    It allows you to selectively encrypt sensitive records with strong multi-layer cryptography, detect potential \
    intrusions and SQL injections and cryptographically compartmentalize data stored in large sharded schemes. \
    Acra's security model guarantees that if your database or your application become compromised, they will not \
    leak sensitive data, or keys to decrypt them."

APP_VENDOR_URL := https://www.cossacklabs.com
APP_VENDOR_NAME := Cossack Labs Limited
APP_VENDOR_EMAIL := dev@cossacklabs.com

#----- Build -------------------------------------------------------------------

BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
## Absolute or relative GOPATH for the 'build' target
BUILD_DIR ?= build
BUILD_DIR_ABS := $(abspath $(BUILD_DIR))
ifeq ($(DOCKER_BUILD_CACHE),true)
DOCKER_BUILD_FLAGS += --no-cache=false
else ifeq ($(DOCKER_BUILD_CACHE),false)
DOCKER_BUILD_FLAGS += --no-cache=true
else ifneq ($(DOCKER_BUILD_CACHE),)
$(error DOCKER_BUILD_CACHE should be either true or false)
else
DOCKER_BUILD_FLAGS += --no-cache=true
endif

#----- Git ---------------------------------------------------------------------

GIT_VERSION := $(shell if [ -d ".git" ]; then git version; fi 2>/dev/null)
ifdef GIT_VERSION
    APP_VERSION := $(shell git describe --tags HEAD 2>/dev/null || printf '0.0.0' | cut -b 1-)
    VCS_HASH := $(shell git rev-parse --verify HEAD)
    VCS_BRANCH := $(shell git branch | grep \* | cut -d ' ' -f2)
else
    APP_VERSION := $(shell date +%s)
    VCS_HASH := 00000000
    VCS_BRANCH := master
endif

#----- Packages ----------------------------------------------------------------

## Application components to include
PKG_COMPONENTS ?= addzone authmanager connector keymaker poisonrecordmaker rollback rotate server translator webconfig

## Installation path prefix for packages
PKG_INSTALL_PREFIX ?= /usr

#----- Docker ------------------------------------------------------------------

DOCKER_BIN := $(shell command -v docker 2> /dev/null)

## Registry host
DOCKER_REGISTRY_HOST ?= localhost
## Registry path, usually - company name
DOCKER_REGISTRY_PATH ?= cossacklabs

## List of extra tags for building, delimiter - single space
DOCKER_EXTRA_BUILD_TAGS ?=
## List of extra tags for pushing into remote registry, delimiter - single space
DOCKER_EXTRA_PUSH_TAGS ?=

# Adapt the branch name to the tag naming convention. For a typical custom branch
# name it looks like replacing 'username/T000_branch_name' to 'username.T000-branch-name'.
# If, despite the naming conventions, the resulting branch name begins with
# a minus symbol, add the word 'branch' to the beginning.
DOCKER_BRANCH_TAGS := $(shell printf "$(VCS_BRANCH)" | \
	tr '/' '.' | tr -c '[:alnum:].-' '-' | \
	awk '/^-/ {printf "branch"$$0; next} {printf $$0}')
ifeq ($(VCS_BRANCH),stable)
    DOCKER_BRANCH_TAGS := $(DOCKER_BRANCH_TAGS) latest
else ifeq ($(VCS_BRANCH),master)
    DOCKER_BRANCH_TAGS := $(DOCKER_BRANCH_TAGS) current
endif

# $(VCS_HASH) is the only tag that must be present to exactly identify the image
DOCKER_BUILD_TAGS := $(VCS_HASH) $(APP_VERSION) $(DOCKER_BRANCH_TAGS) $(DOCKER_EXTRA_BUILD_TAGS)
DOCKER_PUSH_TAGS := $(VCS_HASH) $(APP_VERSION) $(DOCKER_BRANCH_TAGS) $(DOCKER_EXTRA_PUSH_TAGS)

#----- Makefile ----------------------------------------------------------------

COLOR_DEFAULT := \033[0m
COLOR_MENU := \033[1m
COLOR_TARGET := \033[93m
COLOR_ENVVAR := \033[32m
COLOR_COMMENT := \033[90m

#----- Detect OS ---------------------------------------------------------------

# As far as this block is used only for the 'pkg' target, we recognize here
# only the OSs used in it. For the same reason error processing also placed into
# the 'pkg' target.

UNAME := $(shell uname)

ifeq ($(UNAME),Linux)
	OS_NAME := $(shell lsb_release -is 2>/dev/null || printf 'unknown')
	OS_SHORTNAME := $(shell printf "$(OS_NAME)" | tr '[:upper:]' '[:lower:]')
	OS_CODENAME := $(shell lsb_release -cs 2>/dev/null || printf 'unknown')
	OS_VERSION_MAJOR := $(shell (lsb_release -rs 2>/dev/null || printf 'unknown') | cut -d'.' -f1)
	ifeq ($(OS_NAME),$(filter $(OS_NAME),Debian Ubuntu))
		OS_ARCH_DEBIAN := $(shell dpkg --print-architecture 2>/dev/null || printf 'unknown')
	else ifeq ($(OS_NAME),$(filter $(OS_NAME),RedHatEnterpriseServer CentOS))
		ifeq ($(OS_NAME),RedHatEnterpriseServer)
			OS_SHORTNAME := rhel
		endif
		OS_ARCH_RHEL := $(shell arch || printf 'unknown')
	endif
endif


#===== Functions ===============================================================

# set BUILD_CACHE to anything to enable caching
define docker_build
	@$(DOCKER_BIN) image build \
		$(DOCKER_BUILD_FLAGS) \
		--build-arg APP_NAME=$(APP_NAME) \
		--build-arg VERSION='$(APP_VERSION)' \
		--build-arg VCS_URL='$(VCS_URL)' \
		--build-arg VCS_REF='$(VCS_HASH)' \
		--build-arg VCS_BRANCH='$(VCS_BRANCH)' \
		--build-arg BUILD_DATE='$(BUILD_DATE)' \
		--build-arg DOCKER_REGISTRY_PATH='$(DOCKER_REGISTRY_PATH)' \
		$(foreach tag_name,$(DOCKER_BUILD_TAGS), \
			--tag '$(DOCKER_REGISTRY_PATH)/$(1):$(tag_name)') \
		-f ./docker/$(1).dockerfile \
		.
endef

define docker_push
	@$(foreach tag_name,$(DOCKER_PUSH_TAGS), \
		$(DOCKER_BIN) tag \
			'$(DOCKER_REGISTRY_PATH)/$(1):$(VCS_HASH)' \
			'$(DOCKER_REGISTRY_HOST)/$(DOCKER_REGISTRY_PATH)/$(1):$(tag_name)'; \
		$(DOCKER_BIN) push \
			'$(DOCKER_REGISTRY_HOST)/$(DOCKER_REGISTRY_PATH)/$(1):$(tag_name)'; \
	)
endef


#===== Targets =================================================================

.DEFAULT_GOAL := build

.PHONY: help \
    build install test_go test_python test test_all clean \
    docker-build docker-push docker-clean docker \
    pkg deb rpm

#----- Help --------------------------------------------------------------------

## Show this help
help:
	@echo "$(COLOR_MENU)Targets:$(COLOR_DEFAULT)"
	@awk 'BEGIN { FS = ":.*?" }\
		/^## *--/ { print "" }\
		/^## / { split($$0,a,/## /); comment = a[2] }\
		/^[a-zA-Z-][a-zA-Z_-]*:.*?/ {\
			if (length(comment) == 0) { next };\
			printf "  $(COLOR_TARGET)%-15s$(COLOR_DEFAULT) %s\n", $$1, comment;\
			comment = "" }'\
		$(MAKEFILE_LIST)
	@echo "\n$(COLOR_MENU)Properties allowed for overriding:$(COLOR_DEFAULT)"
	@awk 'BEGIN { FS = " *\\?= *" }\
		/^## / { split($$0,a,/## /); comment = a[2] }\
		/^[a-zA-Z][-_a-zA-Z]+ +\?=.*/ {\
			if (length(comment) == 0) { next };\
			printf "  $(COLOR_ENVVAR)%-23s$(COLOR_DEFAULT) - %s\n", $$1, comment;\
			printf "%28s$(COLOR_COMMENT)'\''%s'\'' by default$(COLOR_DEFAULT)\n", "", $$2;\
			comment = "" }'\
		$(MAKEFILE_LIST)
	@echo "$(COLOR_MENU)Usage example:$(COLOR_DEFAULT)\n\
	  make DOCKER_EXTRA_BUILD_TAGS='staging' DOCKER_REGISTRY_HOST=registry.example.com docker-build"

##---- Application -------------------------------------------------------------

## Build the application in the subdirectory (default)
build:
	@GOPATH=$(BUILD_DIR_ABS) go install ./cmd/...

## Build the application and install to the system GOPATH
install:
	go install ./cmd/...

test_go:
	@GOPATH=$(BUILD_DIR_ABS) go test ./cmd/...

## Test the application
test: test_go

# DEPRECATED
test_all: test

# PostgreSQL should be accessible via postgres:postgres@127.0.0.1:5432/postgres
# Alternatively override default connection params via TEST_DB_[HOST|PORT|USERNAME|USER_PASSWORD|NAME]
# Package libpq-dev must be installed for python psycopg2
## Run extra python test
test_python:
	@virtualenv --python=python3 $(BUILD_DIR_ABS)/test_env && \
		$(BUILD_DIR_ABS)/test_env/bin/pip install -r tests/requirements.txt && \
		GOPATH=$(BUILD_DIR_ABS) $(BUILD_DIR_ABS)/test_env/bin/python \
			$(BUILD_DIR_ABS)/src/github.com/cossacklabs/acra/tests/test.py

## Remove build artifacts
clean:
	@test -d $(BUILD_DIR_ABS) && chmod -R u+w $(BUILD_DIR_ABS) || true
	@rm -rf $(BUILD_DIR_ABS)

## Generate keys
keys: install
	@chmod +x scripts/generate-keys.sh
	@scripts/generate-keys.sh

##---- Docker ------------------------------------------------------------------

## Docker : build the image locally
docker-build:
	$(call docker_build,acra-build)
	$(call docker_build,acra-server)
	$(call docker_build,acra-connector)
	$(call docker_build,acra-translator)
	$(call docker_build,acra-keymaker)
	$(call docker_build,acra-tools)
	$(call docker_build,acra-webconfig)
	$(call docker_build,acra-authmanager)
	$(DOCKER_BIN) image prune --force -a \
		--filter label=com.cossacklabs.product.name="$(APP_NAME)" \
		--filter label=com.cossacklabs.docker.container.type="build"

## Docker : tag and push image to remote registry
docker-push:
	$(call docker_push,acra-server)
	$(call docker_push,acra-connector)
	$(call docker_push,acra-translator)
	$(call docker_push,acra-keymaker)
	$(call docker_push,acra-tools)
	$(call docker_push,acra-webconfig)
	$(call docker_push,acra-authmanager)

## Docker : remove stopped containers and dangling images
docker-clean:
	$(DOCKER_BIN) container prune --force \
		--filter label=com.cossacklabs.product.name="$(APP_NAME)"
	$(DOCKER_BIN) image prune --force -a \
		--filter label=com.cossacklabs.product.name="$(APP_NAME)"

## Docker : alias for 'docker-build' target (DEPRECATED)
docker: docker-build

##---- Packages ----------------------------------------------------------------

## Package : build deb/rpm depending on the current OS
pkg: build
ifeq ($(OS_NAME),unknown)
	$(error OS is not detected)
endif
ifeq ($(OS_CODENAME),unknown)
	$(error OS codename is not detected)
endif
ifeq ($(OS_VERSION_MAJOR),unknown)
	$(error OS version is not detected)
endif
ifeq ($(OS_NAME),$(filter $(OS_NAME),Debian Ubuntu))
# acra_0.85.0+stretch_amd64.deb
# acra_0.84.0-53-gd90b699+stretch_amd64.deb
	$(eval PKG_TYPE := deb)
	$(eval PKG_VERSION := $(APP_VERSION)+$(OS_CODENAME))
	$(eval PKG_NAME := $(APP_NAME)_$(PKG_VERSION)_$(OS_ARCH_DEBIAN).deb)
	$(eval PKG_TYPE_SPECIFIC_ARGS := --deb-priority optional \
		--architecture $(OS_ARCH_DEBIAN))
else ifeq ($(OS_NAME),$(filter $(OS_NAME),RedHatEnterpriseServer CentOS))
# acra-0.85.0.centos7.x86_64.rpm
# acra-0.84.0_54_g41001c5.centos7.x86_64.rpm
	$(eval PKG_TYPE := rpm)
	$(eval PKG_VERSION := $(shell printf "$(APP_VERSION)"|sed s/-/_/g))
	$(eval PKG_NAME := $(APP_NAME)-$(PKG_VERSION).$(OS_SHORTNAME)$(OS_VERSION_MAJOR).$(OS_ARCH_RHEL).rpm)
	$(eval PKG_TYPE_SPECIFIC_ARGS := --rpm-summary $(APP_LONG_DESCRIPTION) \
		--architecture $(OS_ARCH_RHEL))
else
	$(error packaging for OS $(OS_NAME) is not supported yet)
endif
	@mkdir -p '$(BUILD_DIR_ABS)/$(PKG_TYPE)'
	@mkdir -p '$(BUILD_DIR_ABS)/$(PKG_TYPE).struct/bin'
	@for p in $(PKG_COMPONENTS); do \
		cp "$(BUILD_DIR_ABS)/bin/acra-$$p" '$(BUILD_DIR_ABS)/$(PKG_TYPE).struct/bin/'; \
	done
	@fpm \
		--input-type dir \
		--output-type $(PKG_TYPE) \
		--name $(APP_NAME) \
		--license '$(APP_LICENSE_NAME)' \
		--url '$(APP_VENDOR_URL)' \
		--description $(APP_SHORT_DESCRIPTION) \
		--vendor '$(APP_VENDOR_NAME)' \
		--maintainer '$(shell printf "$(APP_VENDOR_NAME) <$(APP_VENDOR_EMAIL)>")' \
		--package '$(BUILD_DIR_ABS)/$(PKG_TYPE)/$(PKG_NAME)' \
		--version '$(PKG_VERSION)' \
		--category security \
		--depends libthemis \
		--conflicts acra-ee \
		$(PKG_TYPE_SPECIFIC_ARGS) \
		'$(BUILD_DIR_ABS)/$(PKG_TYPE).struct/bin=$(PKG_INSTALL_PREFIX)'
	@find '$(BUILD_DIR_ABS)' -name \*.$(PKG_TYPE)

## Package : alias for the 'pkg' target (DEPRECATED)
rpm: pkg

## Package : alias for the 'pkg' target (DEPRECATED)
deb: pkg
