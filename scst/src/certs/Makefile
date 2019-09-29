CONFIG_MODULE_SIG_HASH := $(shell sed -n 's/^CONFIG_MODULE_SIG_HASH="\([^"]*\)"$$/\1/p' "$(KDIR)/.config")

all: $(shell grep -q '^CONFIG_MODULE_SIG=y$$' "$(KDIR)/.config" &&	\
	echo module_signing_enabled)

module_signing_enabled: scst_module_key.der scst_module_key.priv

scst_module_key.der scst_module_key.priv: x509.genkey
	openssl req -new -nodes -utf8 -$(CONFIG_MODULE_SIG_HASH) -days 365000 \
		-batch -x509 -config $< -outform DER -out scst_module_key.der \
		-keyout scst_module_key.priv
	chmod 600 $@

.PHONY: module_signing_enabled
