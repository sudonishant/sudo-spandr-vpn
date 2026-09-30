.PHONY: setup test train serve live help

PY ?= python3
VENV ?= .venv
BIN = $(VENV)/bin

help:
	@echo "Sudo Spandr — IPsec X-Ray Command Shortcuts"
	@echo "  make setup   - Create virtualenv and install dependencies"
	@echo "  make test    - Run pytest automated test suite"
	@echo "  make train   - Retrain Random Forest models"
	@echo "  make serve   - Start API and Web Dashboard on port 8000"
	@echo "  make demo    - Run preloaded legacy scenario analysis"

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

test:
	$(BIN)/pytest tests -q -v

train:
	$(BIN)/python -m ipsec_xray.ml.train

serve:
	./run.sh

demo:
	$(BIN)/python -m ipsec_xray.cli analyze samples/legacy_ikev1_aggressive_3des.pcap --profile government
