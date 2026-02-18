.PHONY: verify compile test

PYTHON ?= python

verify: compile test

compile:
	$(PYTHON) -m py_compile env_inspector.py env_inspector_core/*.py tests/*.py

test:
	$(PYTHON) -m pytest -q -s
