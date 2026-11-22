.DEFAULT_GOAL := check

.PHONY: check build test fmt fmt-check clean

check: build test

build:
	@dune build

test:
	@dune runtest

fmt:
	@dune fmt

fmt-check:
	@dune build @fmt

clean:
	@dune clean

