.PHONY: install test test-count

# One-command install: system forensic tools + the FRECE CLI (isolated via pipx).
install:
	sudo ./install.sh

# Run the full unit/integration suite (skips tests needing The Sleuth Kit).
test test-count:
	pytest -q -m "not acceptance"
