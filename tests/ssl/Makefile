SUBJ_C ?= GB
SUBJ_ST ?= London
SUBJ_L ?= London
SUBJ_O ?= Global Security
SUBJ_OU ?= IT
SUBJ_CN ?= Test certificate
SUBJECT ?= /C=$(SUBJ_C)/ST=$(SUBJ_ST)/L=$(SUBJ_L)/O=$(SUBJ_O)/OU=$(SUBJ_OU)/CN=$(SUBJ_CN)
EXPIRE_DAYS ?= 18250

# $1 => group-name
# $2 => name
# $3 => key size in bits (leave empty for default, 2048)
define GenerateRSAKey
$(1)/$(2)/$(2).key:
	@mkdir -p $$(shell dirname "$$@")
	@echo -e "\e[1;37m==> Generating private key $(1)/$(2)/$(2).key\e[0m"
	[ -e "$(1)/$(2)/$(2).key" ] && echo "SKIP" || \
	openssl genrsa -out "$(1)/$(2)/$(2).key" $(if $(3),$(3),2048) && \
	chmod 400 "$(1)/$(2)/$(2).key"

# This rule will be used by make if this exact key belongs to CA cert and is used to sign other certs;
# If there's no config we need, generate it based on base one, use sed to fix paths to cert and private key
$(1)/$(2)/openssl.cnf: $(1).cnf
	@echo -e "\e[1;37m==> Generating OpenSSL config $(1)/$(2)/openssl.cnf based on $(1).cnf\e[0m"
	cat "$(1).cnf" \
		| sed -E 's/dir = .+/dir = $(1)\/$(2)/' \
		| sed -E 's/database = .+/database = $(1)\/$(2)\/index.txt/' \
		| sed -E 's/serial = .+/serial = $(1)\/$(2)\/serial/' \
		| sed -E 's/certificate = .+/certificate = $(1)\/$(2)\/$(2).crt/' \
		| sed -E 's/private_key = .+/private_key = $(1)\/$(2)\/$(2).key/' \
		> "$(1)/$(2)/openssl.cnf"

$(1) += $(1)/$(2)/$(2).key
endef

# $1 => group-name
# $2 => name
# $3 => extensions (leave empty if not needed)
define SignSelf
# Default values for subject, may be redefined before calling this macro
SUBJ_C_$(1)_$(2) ?= $(SUBJ_C)
SUBJ_ST_$(1)_$(2) ?= $(SUBJ_ST)
SUBJ_L_$(1)_$(2) ?= $(SUBJ_L)
SUBJ_O_$(1)_$(2) ?= $(SUBJ_O)
SUBJ_OU_$(1)_$(2) ?= $(SUBJ_OU)
SUBJ_CN_$(1)_$(2) ?= Test CA certificate ($(2))
SUBJECT_$(1)_$(2) ?= /C=$$(SUBJ_C_$(1)_$(2))/ST=$$(SUBJ_ST_$(1)_$(2))/L=$$(SUBJ_L_$(1)_$(2))/O=$$(SUBJ_O_$(1)_$(2))/OU=$$(SUBJ_OU_$(1)_$(2))/CN=$$(SUBJ_CN_$(1)_$(2))

$(1)/$(2)/chain.pem: $(1)/$(2)/$(2).crt
	cat $(1)/$(2)/$(2).crt > $(1)/$(2)/chain.pem

$(1)/$(2)/$(2).crt: $(1)/$(2)/openssl.cnf $(1)/$(2)/$(2).key
	@echo -e "\e[1;37m==> Self-signing $(1)/$(2)/$(2).crt using $(1)/$(2)/$(2).key\e[0m"
	[ -e "$(1)/$(2)/index.txt" ] || touch $(1)/$(2)/index.txt
	[ -e "$(1)/$(2)/serial" ] || echo 01 > $(1)/$(2)/serial
	[ -e "$(1)/$(2)/$(2).crt" ] && echo "SKIP" || \
	openssl req -x509 \
		-key "$(1)/$(2)/$(2).key" \
		-out "$(1)/$(2)/$(2).crt" \
		-sha256 \
		-subj "$$(SUBJECT_$(1)_$(2))" \
		-config "$(1)/$(2)/openssl.cnf" \
		$(if $(3),-extensions $(3)) \
		-days $(EXPIRE_DAYS)

$(1) += $(1)/$(2)/$(2).crt $(1)/$(2)/chain.pem
endef

# $1 => group-name
# $2 => signer name (i.e. ca)
# $3 => signed name (i.e. acra-writer)
# $4 => extensions
define SignCertificate
# Default values for subject, may be redefined before calling this macro
SUBJ_C_$(1)_$(3) ?= $(SUBJ_C)
SUBJ_ST_$(1)_$(3) ?= $(SUBJ_ST)
SUBJ_L_$(1)_$(3) ?= $(SUBJ_J)
SUBJ_O_$(1)_$(3) ?= $(SUBJ_O)
SUBJ_OU_$(1)_$(3) ?= $(SUBJ_OU)
SUBJ_CN_$(1)_$(3) ?= Test certificate ($(3))
SUBJECT_$(1)_$(3) ?= /C=$$(SUBJ_C_$(1)_$(3))/ST=$$(SUBJ_ST_$(1)_$(3))/L=$$(SUBJ_L_$(1)_$(3))/O=$$(SUBJ_O_$(1)_$(3))/OU=$$(SUBJ_OU_$(1)_$(3))/CN=$$(SUBJ_CN_$(1)_$(3))

# full certificate chain, from root CA to *this* certificate,
# just concatenate all those PEM-encoded certificates
$(1)/$(3)/chain.pem: $(1)/$(2)/chain.pem $(1)/$(3)/$(3).crt
	@# ca-then-cert
	@# cat $(1)/$(2)/chain.pem $(1)/$(3)/$(3).crt > $(1)/$(3)/chain.pem
	@# cert-then-ca
	cat $(1)/$(3)/$(3).crt $(1)/$(2)/chain.pem > $(1)/$(3)/chain.pem

# signed crt depends on: openssl config, signed key, signer key, signer crt
$(1)/$(3)/$(3).crt: $(1)/$(2)/openssl.cnf $(1)/$(3)/$(3).key $(1)/$(2)/$(2).key $(1)/$(2)/$(2).crt
	@echo -e "\e[1;37m==> Signing $(1)/$(3)/$(3).crt using $(1)/$(2)/$(2).key\e[0m"
	[ -e "$(1)/$(2)/index.txt" ] || touch $(1)/$(2)/index.txt
	[ -e "$(1)/$(2)/serial" ] || echo 01 > $(1)/$(2)/serial
	if [ -e "$(1)/$(3)/$(3).crt" ]; then \
		echo "SKIP"; \
	else \
		openssl req -new \
			-key "$(1)/$(3)/$(3).key" \
			-out "$(1)/$(3)/$(3).csr" \
			-subj "$$(SUBJECT_$(1)_$(3))" \
		&& openssl ca \
			-config "$(1)/$(2)/openssl.cnf" \
			-in "$(1)/$(3)/$(3).csr" \
			-out "$(1)/$(3)/$(3).crt" \
			-outdir "$(1)/$(2)" \
			-extensions "$(4)" \
			-batch \
			-rand_serial \
			-notext \
			-days "$(EXPIRE_DAYS)" \
		&& rm -f "$(1)/$(3)/$(3).csr"; \
	fi

$(1) += $(1)/$(3)/$(3).crt $(1)/$(3)/chain.pem
endef

# $1 => group-name
# $2 => ca
# $3 => revoked
define RevokeCertificate
$(1)/$(3)/$(3).crt_revoked: $(1)/$(3)/$(3).crt
	@echo -e "\e[1;37m==> Revoking $(1)/$(3)/$(3).crt\e[0m"
	openssl ca \
		-config "$(1)/$(2)/openssl.cnf" \
		-revoke "$(1)/$(3)/$(3).crt"
	touch $(1)/$(3)/$(3).crt_revoked

$(1) += $(1)/$(3)/$(3).crt_revoked
endef

# $1 => group-name
# $2 => ca
define GenerateCRL
$(1)/$(2)/crl.pem: $(1)/$(2)/index.txt
	@echo -e "\e[1;37m==> Generating CRL $(1)/$(2)/crl.pem\e[0m"
	openssl ca \
		-gencrl \
		-config "$(1)/$(2)/openssl.cnf" \
		-out "$(1)/$(2)/crl.pem"

$(1) += $(1)/$(2)/crl.pem
endef

#####################
# BEGIN group-default
$(eval $(call GenerateRSAKey,group-default,ca))
$(eval $(call SignSelf,group-default,ca,v3_ca))

$(eval $(call GenerateRSAKey,group-default,acra-writer))
SUBJ_CN_group-default_acra-writer := Test leaf certificate (acra-writer)
$(eval $(call SignCertificate,group-default,ca,acra-writer,v3_req))

$(eval $(call GenerateRSAKey,group-default,acra-server))
SUBJ_CN_group-default_acra-server := Test leaf certificate (acra-server)
$(eval $(call SignCertificate,group-default,ca,acra-server,v3_req))

$(eval $(call GenerateRSAKey,group-default,acra-writer-revoked))
SUBJ_CN_group-default_acra-writer-revoked := Test leaf certificate (acra-writer-revoked)
$(eval $(call SignCertificate,group-default,ca,acra-writer-revoked,v3_req))
$(eval $(call RevokeCertificate,group-default,ca,acra-writer-revoked))

$(eval $(call GenerateCRL,group-default,ca))

$(eval $(call GenerateRSAKey,group-default,mysql))
SUBJ_CN_group-default_mysql := Test leaf certificate (MySQL)
$(eval $(call SignCertificate,group-default,ca,mysql,v3_req))

$(eval $(call GenerateRSAKey,group-default,postgresql))
SUBJ_CN_group-default_postgresql := Test leaf certificate (PostgreSQL)
$(eval $(call SignCertificate,group-default,ca,postgresql,v3_req))

$(eval $(call GenerateRSAKey,group-default,ocsp-responder))
SUBJ_CN_group-default_ocsp-responder := Test leaf certificate (OCSP responder)
$(eval $(call SignCertificate,group-default,ca,ocsp-responder,v3_OCSP))

group-default: $(group-default)
	find group-default -name '*.old' -delete

.PHONY: group-default
# END group-default
###################

###############################
# BEGIN group-with-intermediate
$(eval $(call GenerateRSAKey,group-with-intermediate,ca))
$(eval $(call SignSelf,group-with-intermediate,ca,v3_ca))

# Create intermediate CA certificate to sign acra-writer and acra-server
$(eval $(call GenerateRSAKey,group-with-intermediate,intermediate-ca))
SUBJ_CN_group-default_acra-writer := Test intermediate CA certificate
$(eval $(call SignCertificate,group-with-intermediate,ca,intermediate-ca,v3_intermediate_ca))

$(eval $(call GenerateRSAKey,group-with-intermediate,acra-writer))
SUBJ_CN_group-default_acra-writer := Test leaf certificate (acra-writer)
$(eval $(call SignCertificate,group-with-intermediate,intermediate-ca,acra-writer,v3_req))

$(eval $(call GenerateRSAKey,group-with-intermediate,acra-server))
SUBJ_CN_group-default_acra-server := Test leaf certificate (acra-server)
$(eval $(call SignCertificate,group-with-intermediate,intermediate-ca,acra-server,v3_req))

$(eval $(call GenerateRSAKey,group-with-intermediate,acra-writer-revoked))
SUBJ_CN_group-default_acra-writer-revoked := Test leaf certificate (acra-writer-revoked)
$(eval $(call SignCertificate,group-with-intermediate,intermediate-ca,acra-writer-revoked,v3_req))
$(eval $(call RevokeCertificate,group-with-intermediate,intermediate-ca,acra-writer-revoked))

$(eval $(call GenerateCRL,group-with-intermediate,intermediate-ca))

$(eval $(call GenerateRSAKey,group-with-intermediate,mysql))
SUBJ_CN_group-default_mysql := Test leaf certificate (MySQL)
$(eval $(call SignCertificate,group-with-intermediate,ca,mysql,v3_req))

$(eval $(call GenerateRSAKey,group-with-intermediate,postgresql))
SUBJ_CN_group-default_postgresql := Test leaf certificate (PostgreSQL)
$(eval $(call SignCertificate,group-with-intermediate,ca,postgresql,v3_req))

$(eval $(call GenerateRSAKey,group-with-intermediate,ocsp-responder))
SUBJ_CN_group-default_ocsp-responder := Test leaf certificate (OCSP responder)
$(eval $(call SignCertificate,group-with-intermediate,ca,ocsp-responder,v3_OCSP))

$(eval $(call GenerateRSAKey,group-with-intermediate,intermediate-ocsp-responder))
SUBJ_CN_group-default_intermediate-ocsp-responder := Test leaf certificate (intermediate OCSP responder)
$(eval $(call SignCertificate,group-with-intermediate,intermediate-ca,intermediate-ocsp-responder,v3_OCSP))

group-with-intermediate: $(group-with-intermediate)
	find group-with-intermediate -name '*.old' -delete

.PHONY: group-with-intermediate
# END group-with-intermediate
#############################

all: group-default
