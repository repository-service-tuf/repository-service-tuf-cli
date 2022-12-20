#################################################
Repository Service for TUF Command Line Interface
#################################################

|Tests and Lint| |Coverage|

.. |Tests and Lint| image:: https://github.com/vmware/repository-service-tuf-cli/actions/workflows/ci.yml/badge.svg
  :target: https://github.com/vmware/repository-service-tuf-cli/actions/workflows/ci.yml
.. |Coverage| image:: https://codecov.io/gh/vmware/repository-service-tuf-cli/branch/main/graph/badge.svg
  :target: https://codecov.io/gh/vmware/repository-service-tuf-cli

The Repository Service for TUF Command Line Interface (CLI) is a CLI Python
application to manage the Repository Service for TUF.

The CLI supports the initial setup, termed a ceremony, where the first repository
metadata are signed and the service is configured, generating tokens to be used
by integration (i.e., CI/CD tools).

This CLI is part of the Repository Service for TUF (RSTUF).

.. note::

    Not a functional tool, it is still in the development stage. Wait for release 0.0.1

Installation
============
Using pip:

.. code:: shell

    $ pip install repository-service-tuf

Usage
=====
Please, check the `Repository Service for TUF Guide
<https://repository-service-tuf.readthedocs.io/en/latest/guide/repository-service-tuf-cli/index.html>`_
for more details.

Contributing
============

Please, visit the `Repository Service for TUF Development Guide
<https://repository-service-tuf.readthedocs.io/en/latest/devel/index.html#development-guide>`_.

Check our `CONTRIBUTING.rst <https://github.com/vmware/repository-service-tuf-cli/blob/main/CONTRIBUTING.rst>`_
for more details on how to contribute to this repository.

License
=======
`MIT <https://github.com/vmware/repository-service-tuf-cli/blob/main/LICENSE>`_
