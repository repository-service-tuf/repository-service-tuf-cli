Command Line Interface Design
=============================

Context level
-------------

The ``repository-service-tuf``, in the context perspective, is a command line tool. It sends
HTTP requests to ``repository-service-tuf-api``.

.. image:: /_static/repository-service-tuf-cli-C1.png


Container level
---------------

The ``repository-service-tuf``, in the container perspective, is a command line tool that
interacts to the ``repository-service-tuf-api``.

``repository-service-tuf`` reads the settings configuration from config file
See: ``--config/-c``, default: ``$HOME/.rstuf.yml``.

``repository-service-tuf`` writes the ``payload.json`` or the specified file
with option ``-f/--file`` with ``ceremony`` subcommand.

``repository-service-tuf`` writes also upon request all the metadata files in
``metadata`` folder if used ``-s/--save``with ``ceremony`` subcommand.


.. image:: /_static/repository-service-tuf-cli-C2.png
