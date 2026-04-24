# SkillFortifyBench — Build + Run Targets
# Per LLD-08 §4 release pipeline

SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON := PYTHONHASHSEED=0 python
OUTPUT := benchmarks/skills

.PHONY: help generate verify clean benchmark

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

generate:  ## Generate 540 benchmark skills (seed=42)
	$(PYTHON) -m benchmarks.generator --output $(OUTPUT) --seed 42

verify:  ## Verify existing benchmark against manifest
	$(PYTHON) -m benchmarks.generator --output $(OUTPUT) --verify-only

benchmark: generate  ## Generate + scan + compute metrics
	@echo "=== Scanning generated skills ==="
	skillfortify scan $(OUTPUT) --format json --severity-threshold medium > .skfval-tmp/scan-results.json || true
	@echo "=== Benchmark complete ==="

clean:  ## Remove generated skills (keeps source)
	rm -rf $(OUTPUT)/skills $(OUTPUT)/manifest.json $(OUTPUT)/attack_taxonomy.json

lint:  ## Run AST preflight scan on generator package
	$(PYTHON) -c "from benchmarks.generator.preflight import ast_scan_package; \
		from pathlib import Path; v = ast_scan_package(Path('benchmarks/generator')); \
		print(f'{len(v)} violations') if v else print('Clean')"

test:  ## Run all tests
	PYTHONHASHSEED=0 pytest tests/ -q
