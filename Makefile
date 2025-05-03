.PHONY: all docs tests coverage reformat requirements precommit run-dev clone-umbrella ft-das ft-signed stop clean help

all: help

reformat:  ## Reformat code with black and isort
	black -l 79 .
	isort -l79 --profile black .

tests:  ## Run all tests
	tox -r

precommit:  ## Install and run pre-commit hooks
	pre-commit install
	pre-commit run --all-files --show-diff-on-failure

coverage:  ## Run tests with coverage
	coverage report
	coverage html -i

docs:  ## Build documentation
	tox -e docs

run-dev: export API_VERSION = dev
run-dev: export WORKER_VERSION = dev
run-dev:  ## Run the development environment
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
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-das.sh $(CLI_VERSION) $(PYTEST_GROUP) $(SLOW)

ft-signed:
# Use "GITHUB_ACTION" to identify if we are running from a GitHub action.
ifeq ($(GITHUB_ACTION),)
	$(MAKE) clone-umbrella
endif
	docker compose run --env UMBRELLA_PATH=rstuf-umbrella --rm rstuf-ft-runner bash rstuf-umbrella/tests/functional/scripts/run-ft-signed.sh $(CLI_VERSION) $(PYTEST_GROUP) $(SLOW)

stop:  ## Stop the development environment
	docker compose down -v

clean:  ## Clean up the environment
	$(MAKE) stop
	docker compose rm --force
	rm -rf ./data
	rm -rf ./data_test

help:  ## Show this help message
	@echo "Makefile commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'	
	@echo