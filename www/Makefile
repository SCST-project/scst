check:
	@command -v tidy >/dev/null 2>&1 || { \
		echo "Error: tidy is required to check the website." >&2; \
		exit 1; \
	}
	@status=0; \
	for f in $$(find . -name '*.html'); do \
		tidy -e "$$f" || status=$$?; \
	done; \
	exit $$status

.PHONY: check
