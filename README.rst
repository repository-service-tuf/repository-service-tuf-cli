##############################
Kaprien Command Line Interface
##############################

This is a Command Line Interface for Kaprien

.. note::

    Not a functional tool, it is still in development stage. Wait release 0.0.1

Development
###########

Requirements:
=============

These are the minimum requirements for the Kaprien program to work

- Python >=3.9
- Pipenv


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


Install ``kaprien`` in your development environment


Installing the Kaprien program straight from the root.

.. code:: shell

    $ pip install -e .


Running Kaprien

.. code:: shell

    $ kaprien

    Usage: kaprien [OPTIONS] COMMAND [ARGS]...

    KAPRIEN Command Line Interface (CLI) helps you to manage your KAPRIEN.



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

