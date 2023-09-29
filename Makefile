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
	pre-commit run --all-files --show-diff-on-failure

coverage:
	coverage report
	coverage html -i

docs:
	tox -e docs

run-dev: export API_VERSION = dev
run-dev: export WORKER_VERSION = dev
run-dev:
	docker pull ghcr.io/repository-service-tuf/repository-service-tuf-api:dev
	docker pull ghcr.io/repository-service-tuf/repository-service-tuf-worker:dev
	docker compose -f docker-compose.yml up --remove-orphans


clone-umbrella:
	if [ -d rstuf-umbrella ];\
		then \
		cd rstuf-umbrella && git pull;\
	else \
		git clone https://github.com/repository-service-tuf/repository-service-tuf.git rstuf-umbrella;\
	fi

ft-das:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-das.sh $(CLI_VERSION)

ft-signed:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-signed.sh $(CLI_VERSION)

stop:
	docker compose down -v

clean:
	$(MAKE) stop
	docker compose rm --force
	rm -rf ./data
	rm -rf ./data_test
