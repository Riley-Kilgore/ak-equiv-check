AIKEN ?= aiken

.PHONY: setup-smoke test blaster-smoke sentinel

setup-smoke:
	cd tool && uv sync --locked
	cd tool/blaster-backend && lake build CardanoLedgerApi
	cd tool && uv run equiv-checker compare tests/fixtures/aiken-package --old-aiken "$$(command -v $(AIKEN))" --new-aiken "$$(command -v $(AIKEN))" --old-revision smoke --new-revision smoke --strict
	cd tool && uv run python -m unittest tests.test_real_blaster -v

test:
	cd tool && uv run python -m unittest discover -s tests -v

blaster-smoke:
	cd tool && uv run python -m unittest tests.test_real_blaster -v

sentinel:
	cd tool && uv run equiv-checker sentinel --strict
