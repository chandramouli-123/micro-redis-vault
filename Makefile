.PHONY: all build test run cli bench clean

all: build test

build:
	@./build.sh

test:
	@python3 test_micro_redis_vault.py

run:
	@python3 micro_redis_vault.py --web

cli:
	@python3 micro_redis_vault.py cli

bench:
	@python3 benchmark.py

clean:
	@rm -f *.log *.bin *.enc *.pyc
	@rm -rf __pycache__
