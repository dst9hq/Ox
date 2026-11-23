.DEFAULT_GOAL := check

.PHONY: check build test fmt fmt-check promote docs clean

check: build test

build:
	@dune build

test:
	@dune runtest

fmt:
	@dune fmt

fmt-check:
	@dune build @fmt

promote:
	@dune promote

docs:
	@dune build @doc

clean:
	@dune clean

