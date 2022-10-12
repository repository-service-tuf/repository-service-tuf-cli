Command Line Interface Design
=============================

Context level
-------------

The ``repository-service-tuf``, in the context perspective, is a command line tool. It sends
HTTP requests to ``repository-service-tuf-api``.

.. uml:: ../../diagrams/repository-service-tuf-cli-C1.puml


Container level
---------------

The ``repository-service-tuf``, in the container perspective, is a command line tool that
interacts to the ``repository-service-tuf-api``.

``repository-service-tuf`` writes a settings configuration in the file
``$HOME/.rstuf.ini`` with ``login`` subcommand.

``repository-service-tuf`` writes the ``payload.json`` or the specified file with
option ``-f/--file`` with ``ceremony`` subcommand.

``repository-service-tuf`` writes also upon request all the metadata files in
``metadata`` folder if used ``-s/--save``with ``ceremony`` subcommand.


.. uml:: ../../diagrams/repository-service-tuf-cli-C2.puml
