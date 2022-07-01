reformat:
	black -l 79 .
	isort -l79 --profile black .

tests:
	tox -r