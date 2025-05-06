GO_BIN?=$(shell pwd)/.bin/go
PYTHON_PATH?=$(shell pwd)/.bin/python

GOCI_LINT_V?=v1.64.7
PRE_COMMIT_V?=v3.8


export PYTHONPATH=$(PYTHON_PATH)
SHELL:=env PATH=$(GO_BIN):$(PYTHON_PATH)/bin:$(PATH) $(SHELL)

.PHONY: install-tools
install-tools: ## Install golangci-lint, pre-commit & everything in tools.go
	mkdir -p ${GO_BIN}
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % sh -c 'GOBIN=${GO_BIN} go install %'
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/${GOCI_LINT_V}/install.sh' | sh -s -- -b ${GO_BIN} ${GOCI_LINT_V}
	python -m venv ${PYTHON_PATH}
	pip install pre-commit==${PRE_COMMIT_V}
	pre-commit install --hook-type commit-msg --hook-type pre-commit

.PHONY: lint
lint: ## Run golangci linters
	golangci-lint run -v ./...

.PHONY: format
format: ## Format source code based on golangci configuration
	golangci-lint run --fix -v ./...

.PHONY: test
test: ## Run unit tests
	go test -v ./...

.PHONY: generate
generate: ## Run commands described by //go:generate directives within source code
	go generate ./...
