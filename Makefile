SHELL=/usr/bin/env bash
GO_VERSION=$(shell cat '.go-version')
CMD_COLOR_ON=\033[32m\xE2\x9c\x93
CMD_COLOR_OFF=\033[0m

.PHONY: mage
mage:
	@go install github.com/magefile/mage
	@printf "${CMD_COLOR_ON} Mage installed\n${CMD_COLOR_OFF}"

.PHONY: clean
clean:
	@printf "${CMD_COLOR_ON} Clean up build artifacts\n${CMD_COLOR_OFF}"
