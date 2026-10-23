# Record the same compile_c recipe used for objects, without compiling CLI code.
PYTHON ?= python3
.PHONY: compile-commands $(COMMAND_SOURCES:.c=.compile-command)
compile-commands: $(COMMAND_SOURCES:.c=.compile-command)

$(COMMAND_SOURCES:.c=.compile-command): %.compile-command: %.c
	@test -n "$(COMPILE_COMMANDS_DIR)" || { echo "Use make compile-commands at the repository root" >&2; exit 1; }
	@$(PYTHON) ../../scripts/compile_commands.py record "$(COMPILE_COMMANDS_DIR)" -- \
		$(call compile_c,$<,$(<:.c=.o))
