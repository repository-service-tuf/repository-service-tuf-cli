# Kaprien Command Line Interface

This is a Command Line Interface for Kaprien

> **NOTE:** Not a functional program, it is still in development stage.

## Development

Requirements:

These are the minimum requirements for the Kaprien program to work

- Python >=3.9
- Pipenv


### Preparing the environment

After installing Python, install the pipenv tool.
```shell
$ pip install pipenv
```

Creating a virtual environment for this project.
```shell
$ pipenv shell
```

Install requirements from Pipfile.lock
The flag -d will install the development requirements
```Shell
$ pipenv install -d
```

### How to install new requirements

Install requirements package
The flag -d will install the development requirements
```Shell
pipenv install -d <package>
pipenv install <package>
```

Update all project requirements
```shell
$ make requirements
```

### Tests

Perform automated testing with the TOX tool.
```shell
$ tox
```

### Install Kaprien

Installing the Kaprien program straight from the root.
```shell
$ pip install -e .
```

### Running Kaprien

```shell
$ kaprien

 Usage: kaprien [OPTIONS] COMMAND [ARGS]...

 KAPRIEN Command Line Interface (CLI) helps you to manage your KAPRIEN.
```

