# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

SRC_DIR := .
MD_OUT_DIR := docs/commands
SRC := $(wildcard $(SRC_DIR)/*.pl)
MD_OUT := $(patsubst $(SRC_DIR)/%.pl, $(MD_OUT_DIR)/%.md, $(SRC))

all: docs

docs/commands/check_sophos_xg_%.md: check_sophos_xg_%.pl
	@echo "# $<" > $@
	@echo "" >> $@
	@echo '```console' >> $@
	./$< --help  >> $@ || test $$? -eq 3
	@echo '```' >> $@

docs: generate_md
	mkdocs build

generate_md: $(MD_OUT)


.PHONY: generate_md all docs
