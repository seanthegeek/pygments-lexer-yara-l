.PHONY: test server

test:
	pytest

server:
	python server.py

.DEFAULT_GOAL := test
