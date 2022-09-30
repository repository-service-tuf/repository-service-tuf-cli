#############################################
TUF Repository Service Command Line Interface
#############################################

|Tests and Lint| |Coverage|

.. |Tests and Lint| image:: https://github.com/kaprien/tuf-repository-service-cli/actions/workflows/ci.yml/badge.svg
  :target: https://github.com/kaprien/tuf-repository-service-cli/actions/workflows/ci.yml
.. |Coverage| image:: https://codecov.io/gh/kaprien/tuf-repository-service-cli/branch/main/graph/badge.svg
  :target: https://codecov.io/gh/kaprien/tuf-repository-service-cli

TUF Repository Service Command Line Interface (CLI).

This CLI is part of TUF Repository Service (TRS).

.. note::

    Not a functional tool, it is still in development stage. Wait release 0.0.1

Development
###########

Requirements:
=============

- Python >=3.9
- Pipenv

Getting source code
===================

`Fork <https://docs.github.com/en/get-started/quickstart/fork-a-repo>`_ the
repository on `GitHub <https://github.com/kaprien/tuf-repository-service-cli>`_ and
`clone <https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository>`_
it to your local machine:

.. code-block:: console

    git clone git@github.com:YOUR-USERNAME/tuf-repository-service-cli.git

Add a `remote
<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork>`_ and
regularly `sync <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork>`_ to make sure
you stay up-to-date with our repository:

.. code-block:: console

    git remote add upstream https://github.com/kaprien/tuf-repository-service-cli
    git checkout main
    git fetch upstream
    git merge upstream/main


Preparing the environment
=========================

After installing Python, install the pipenv tool.

.. code:: shell

    $ pip install pipenv


Creating a virtual environment for this project.

.. code:: shell

    $ pipenv shell


Install requirements from Pipfile

The flag -d will install the development requirements

.. code:: shell

    $ pipenv install -d


.. note::

    MacOS running on Macbooks M1

    For developers, after above command, run

    .. code:: shell

        $ pip uninstall cryptography cffi -y
        $ pip cache purge
        $ LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography


Running TRS CLI

.. code:: shell

    $ trs-cli

    Usage: trs-cli [OPTIONS] COMMAND [ARGS]...

    TUF Repository Service Command Line Interface (CLI).



How to add new requirements
===========================

Install requirements package

The flag -d will install the development requirements

.. code:: shell

    $ pipenv install -d <package>
    $ pipenv install <package>


Update all project requirements
-------------------------------

.. code:: shell

    $ make requirements

Tests
=====

Perform automated testing with the TOX tool.

.. code:: shell

    $ tox

