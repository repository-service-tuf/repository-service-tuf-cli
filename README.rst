#################################################
Repository Service for TUF Command Line Interface
#################################################

|Tests and Lint| |Coverage|

.. |Tests and Lint| image:: https://github.com/vmware/repository-service-tuf-cli/actions/workflows/ci.yml/badge.svg
  :target: https://github.com/vmware/repository-service-tuf-cli/actions/workflows/ci.yml
.. |Coverage| image:: https://codecov.io/gh/vmware/repository-service-tuf-cli/branch/main/graph/badge.svg
  :target: https://codecov.io/gh/vmware/repository-service-tuf-cli

Repository Service for TUF Command Line Interface (CLI).

This CLI is part of the Repository Service for TUF (RSTUF).

.. note::

    Not a functional tool, it is still in the development stage. Wait for release 0.0.1

Development
###########

Requirements:
=============

- Python >=3.9
- Pipenv

Getting the source code
=======================

`Fork <https://docs.github.com/en/get-started/quickstart/fork-a-repo>`_ the
repository on `GitHub <https://github.com/vmware/repository-service-tuf-cli>`_ and
`clone <https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository>`_
it to your local machine:

.. code-block:: console

    git clone git@github.com:YOUR-USERNAME/repository-service-tuf-cli.git

Add a `remote
<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork>`_ and
regularly `sync <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork>`_ to make sure
you stay up-to-date with our repository:

.. code-block:: console

    git remote add upstream https://github.com/vmware/repository-service-tuf-cli
    git checkout main
    git fetch upstream
    git merge upstream/main


Preparing the environment
=========================

After installing Python, install the pipenv tool:

.. code:: shell

    $ pip install pipenv


Create a virtual environment for this project:

.. code:: shell

    $ pipenv shell


Install the requirements from the Pipfile.

The flag -d will install the development requirements:

.. code:: shell

    $ pipenv install -d


.. note::

    macOS running on MacBook M1

    For developers, after the above command, run:

    .. code:: shell

        $ pip uninstall cryptography cffi -y
        $ pip cache purge
        $ LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography


Running RSTUF CLI:

.. code:: shell

    $ rstuf

    Usage: rstuf [OPTIONS] COMMAND [ARGS]...

    Repository Service for TUF Command Line Interface (CLI).



How to add new requirements
===========================

Install the requirements package.

The flag -d will install the development requirements.

.. code:: shell

    $ pipenv install -d <package>
    $ pipenv install <package>


Update all project requirements
-------------------------------

.. code:: shell

    $ make requirements

Tests
=====

Perform automated testing with the tox tool:

.. code:: shell

    $ tox


Installing & enabling pre-commit
================================

The pre-commit tool is installed as part of the development requirements.

To automatically run checks before you commit your changes you should install
the git hook scripts with **pre-commit**:

.. code:: shell

    $ pre-commit install

