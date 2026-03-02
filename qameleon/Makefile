.PHONY: setup test test-unit test-security coverage lint format bench dashboard dashboard-tls docker-build docker-run build-c clean-c check-c verify-tamarin verify-pv clean

setup:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v -m unit

test-security:
	pytest tests/security/ -v -m security

coverage:
	pytest tests/ --cov=src/qameleon --cov-report=html --cov-report=term

lint:
	ruff check src/ tests/
	mypy src/

format:
	black src/ tests/
	ruff check --fix src/ tests/

bench:
	python benchmarks/run_all_benchmarks.py

dashboard:
	cd src && python -m qameleon.dashboard.app

dashboard-tls:
	QAMELEON_DASHBOARD_TLS=true cd src && python -m qameleon.dashboard.app

docker-build:
	docker build -t qameleon:latest .

docker-run:
	docker run -p 8000:8000 --env-file .env qameleon:latest

build-c:
	python src/qameleon/crypto_primitives/c_accel/build.py

clean-c:
	rm -rf src/qameleon/crypto_primitives/c_accel/lib/

check-c:
	python -c "from qameleon.crypto_primitives.c_accel import is_accelerated; print('C accel:', is_accelerated())"

verify-tamarin:
	tamarin-prover formal_verification/tamarin/*.spthy

verify-pv:
	proverif formal_verification/proverif/*.pv

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage dist build *.egg-info
