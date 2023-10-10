==============================================
Contributing to Repository Service for TUF CLI
==============================================

We welcome contributions from the community and first want to thank you for
taking the time to contribute!

Please familiarize yourself with the `Code of Conduct
<https://repository-service-tuf.readthedocs.io/en/latest/devel/contributing.html#id1>`_
before contributing.

DCO
===

Before you start working with Repository Service for TUF, please read our
`Developer Certificate of Origin <https://cla.vmware.com/dco>`_.
All contributions to this repository must be signed as described on that page.

To acknowledge the Developer Certificate of Origin (DCO), sign your commits
by appending a ``Signed-off-by:
Your Name <example@domain.com>`` to each git commit message (see `git commit
--signoff <https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---signoff>`_).
Your signature certifies that you wrote the patch or have the right to pass it
on as an open-source patch.

Getting started
===============

We welcome many different types of contributions and not all of them need a
Pull Request. Contributions may include:

* New features and proposals
* Documentation
* Bug fixes
* Issue Triage
* Answering questions and giving feedback
* Helping to onboard new contributors
* Other related activities

Development
===========

Requirements
-------------

- Python >=3.9
- Pipenv
- PostgreSQL

.. note::
    Make sure python versions of pip and pipenv match, as otherwise installing the requirements from the Pipfile may fail.

Getting the source code
-----------------------

`Fork <https://docs.github.com/en/get-started/quickstart/fork-a-repo>`_ the
repository on `GitHub <https://github.com/repository-service-tuf/repository-service-tuf-cli>`_ and
`clone <https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository>`_
it to your local machine:

.. code-block:: console

    git clone git@github.com:YOUR-USERNAME/repository-service-tuf-cli.git

Add a `remote
<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork>`_ and
regularly `sync <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork>`_ to make sure
you stay up-to-date with our repository:

.. code-block:: console

    git remote add upstream https://github.com/repository-service-tuf/repository-service-tuf-cli
    git checkout main
    git fetch upstream
    git merge upstream/main

Preparing the environment
-------------------------

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


Running checks with pre-commit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The pre-commit tool is installed as part of the development requirements.

To automatically run checks before you commit your changes you should run:

.. code:: shell

    $ make precommit

This will install the git hook scripts for the first time, and run the
pre-commit tool.
Now ``pre-commit`` will run automatically on ``git commit``.


Running RSTUF CLI
~~~~~~~~~~~~~~~~~

.. code:: shell
    $ pip install -e .

.. code:: shell

    $ pip install -e .

    $ rstuf

    Usage: rstuf [OPTIONS] COMMAND [ARGS]...

    Repository Service for TUF Command Line Interface (CLI).

How to add new requirements
---------------------------

Install the requirements package.

The flag -d will install the development requirements.

.. code:: shell

    $ pipenv install -d <package>
    $ pipenv install <package>


Update all project requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: shell

    $ make requirements

Tests
-----

Perform automated testing with the tox tool:

.. code:: shell

    $ tox