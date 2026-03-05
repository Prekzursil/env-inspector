.PHONY: verify compile test

PYTHON ?= python3

verify: compile test

compile:
	$(PYTHON) -m py_compile env_inspector.py env_inspector_core/*.py env_inspector_gui/*.py tests/*.py scripts/quality/*.py

test:
	$(PYTHON) -m pytest -q -s
