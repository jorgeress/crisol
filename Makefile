.PHONY: install rules scan bench test clean
VENV=.venv
PY=$(VENV)/bin/python

install:
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements.txt

rules:
	PYTHONPATH=src $(PY) -m yardstick.cli rules

# make scan SAMPLE=/ruta/muestra
scan:
	PYTHONPATH=src $(PY) -m yardstick.cli scan $(SAMPLE)

bench:
	$(PY) bench/harness.py --rules rules --goodware corpus/goodware --malware corpus/malware

test:
	PYTHONPATH=src $(PY) -m pytest -q

clean:
	rm -rf $(VENV) reports/*.html reports/*.json bench/*.json
