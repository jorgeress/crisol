.PHONY: install hooks rules scan corpus bench sandbox-bench test clean
VENV=.venv
PY=$(VENV)/bin/python

install:
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements.txt

# instala el hook que impide subir muestras al repo
hooks:
	install -m 755 scripts/pre-commit .git/hooks/pre-commit
	@echo "[ok] hook pre-commit instalado"

rules:
	PYTHONPATH=src $(PY) -m yardstick.cli rules

# make scan SAMPLE=/ruta/muestra
scan:
	PYTHONPATH=src $(PY) -m yardstick.cli scan $(SAMPLE)

# make corpus TAG=exe LIMIT=30 MAXFAM=3   (necesita MB_API_KEY o .mb_api_key)
TAG?=exe
LIMIT?=30
MAXFAM?=3
corpus:
	$(PY) bench/fetch_malwarebazaar.py --tag $(TAG) --limit $(LIMIT) --max-per-family $(MAXFAM)

bench:
	$(PY) bench/harness.py --rules rules --goodware corpus/goodware --malware corpus/malware

# el mismo bench, pero con el analizador aislado (sin red, sin $$HOME, repo ro)
sandbox-bench:
	scripts/sandbox.sh $(PY) bench/harness.py --rules rules \
		--goodware corpus/goodware --malware corpus/malware

test:
	PYTHONPATH=src $(PY) -m pytest -q

clean:
	rm -rf $(VENV) reports/*.html reports/*.json bench/*.json
