.PHONY: help install setup test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install hashcracker as a Python package
	pip install -e .

setup: ## Install external tools and wordlists
	python3 hash_cracker.py --setup

test: ## Run unit tests
	python3 -m pytest tests/ -v

lint: ## Run flake8 linter
	flake8 hashcracker/ --max-line-length=120 --ignore=E501,W503

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true

identify: ## Example: identify a hash (usage: make identify HASH=<hash>)
	python3 hash_cracker.py -H $(HASH)

crack: ## Example: crack a hash (usage: make crack HASH=<hash>)
	python3 hash_cracker.py -H $(HASH) --crack
