.PHONY: help install install-dev test test-cov lint fmt typecheck clean build docs

PYTHON := python
PIP    := pip
PYTEST := pytest
MYPY   := mypy
RUFF   := ruff

help:           ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:        ## Install package in production mode
	$(PIP) install -e .

install-dev:    ## Install package with all dev dependencies
	$(PIP) install -e ".[dev]"
	pre-commit install

test:           ## Run the test suite
	$(PYTEST) tests/ -v

test-cov:       ## Run tests with coverage report
	$(PYTEST) tests/ -v --cov=aumai_specs --cov-report=term-missing --cov-report=html:htmlcov

test-fast:      ## Run tests excluding slow/integration tests
	$(PYTEST) tests/ -v -m "not slow and not integration"

lint:           ## Run ruff linter
	$(RUFF) check src/ tests/ examples/

fmt:            ## Auto-format with ruff
	$(RUFF) format src/ tests/ examples/
	$(RUFF) check --fix src/ tests/ examples/

typecheck:      ## Run mypy strict type checking
	$(MYPY) src/aumai_specs

check: lint typecheck test  ## Run lint + typecheck + tests

clean:          ## Remove build artifacts and caches
	rm -rf dist/ build/ .eggs/ *.egg-info
	rm -rf htmlcov/ .coverage coverage.xml
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:          ## Build wheel and sdist
	$(PYTHON) -m build

quickstart:     ## Run the quickstart example
	$(PYTHON) examples/quickstart.py
