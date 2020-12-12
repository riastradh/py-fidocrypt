default-target: all
default-target: .PHONY
.PHONY:

PYTHON = python

FETCH = curl -L -o

all: .PHONY
	rm -rf build && \
	$(PYTHON) setup.py build

sdist: .PHONY
	$(PYTHON) setup.py sdist

lint: .PHONY
	$(PYTHON) -m flake8 src test

check: .PHONY
check: all
check: lint
	PYTHONPATH="`pwd`/build/lib" \
	$(PYTHON) -m pytest --pyargs fidocrypt

env: .PHONY
	PYTHONPATH="`pwd`/build/lib" \
	PYTHON="$(PYTHON)" \
	$(SHELL)

clean: .PHONY
	-rm -rf build
	-rm -rf dist
	-rm -rf fidocrypt.egg-info
