DAFNY ?= $(shell command -v dafny 2>/dev/null || printf '%s' "verify/bin/dafny-4.11.0/dafny/dafny")
OPA ?= $(shell command -v opa 2>/dev/null || printf '%s' "verify/bin/opa")

.PHONY: install test verify verify-formal

install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest

verify:
	python -m pipeline.verify
	$(MAKE) verify-formal

verify-formal:
	$(DAFNY) verify verify/Gate.dfy
	$(DAFNY) verify verify/Gate.dfy verify/Authority.dfy
	$(OPA) test verify/
	python verify/difftest/run.py
	python verify/difftest/authority.py
