check:
	find -name '*.html' | while read f; do tidy -e < "$$f" | sed "s|^-e|$$f|"; done
