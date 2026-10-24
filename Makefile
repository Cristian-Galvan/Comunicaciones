ifeq ($(OS),Windows_NT)
PYTHON ?= py -3
else
PYTHON ?= python3
endif

.PHONY: install pki test demo demo-plano demo-tls clean

install:
	$(PYTHON) -m pip install -r requirements.txt

pki:
	mkdir -p pki/out

test:
	$(PYTHON) -c "import pytest, sys; status = pytest.main(['-q']); sys.exit(0 if status == 5 else status)"

demo:
	bash tests/demo_completa.sh

demo-plano:
	echo "Demo en texto plano pendiente de implementación."

demo-tls:
	echo "Demo TLS pendiente de implementación."

clean:
	rm -rf pki/out .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf logs