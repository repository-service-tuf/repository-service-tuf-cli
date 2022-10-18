.PHONY: all docs tests coverage reformat requirements

reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r

requirements:
	pipenv requirements > requirements.txt
	pipenv requirements --dev > requirements-dev.txt

coverage:
	coverage report
	coverage html -i

docs:
	tox -e docs