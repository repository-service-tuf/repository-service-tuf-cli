.PHONY: all docs tests coverage reformat requirements

reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r

requirements:
	pipenv lock
	pipenv requirements > requirements.txt
	pipenv requirements --dev > requirements-dev.txt

precommit:
	pre-commit install
	pre-commit autoupdate
	pre-commit run --all-files --show-diff-on-failure

coverage:
	coverage report
	coverage html -i

docs:
	tox -e docs