
==============================
Repository Service for TUF CLI
==============================

``repository-service-tuf`` is a Command Line Interface for the Repository Service for TUF.

Installation
============

Using pip:

.. code:: shell

    $ pip install repository-service-tuf

.. code:: shell

    ❯ rstuf -h

    Usage: rstuf [OPTIONS] COMMAND [ARGS]...

    Repository Service for TUF Command Line Interface (CLI).

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --config        -c  TEXT  Repository Service for TUF config file. [default: /Users/kairo/.rstuf.yml]                 │
    │ --version                 Show the version and exit.                                                                 │
    │ --autocomplete            Enable tab autocompletion and exit.                                                        │
    │ --help          -h        Show this message and exit.                                                                │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ admin                             Administrative  Commands                                                           │
    │ admin-legacy                      Administrative (Legacy) Commands                                                   │
    │ artifact                          Artifact Management Commands                                                       │
    │ key                               Cryptographic Key Commands                                                         │
    │ task                              Task Management Commands                                                           │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

.. rstuf-cli-admin

Administration (``admin``)
==========================


.. note::

    Find the legacy administrative commands in the ``admin-legacy`` command.
    The guide is available in :doc:`admin_legacy`.

It executes administrative commands to the Repository Service for TUF.

.. code:: shell

    ❯ rstuf admin

    Usage: rstuf admin [OPTIONS] COMMAND [ARGS]...

    Administrative Commands

    ╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --help  -h    Show this message and exit.                                                                             │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ ceremony                 Bootstrap Ceremony to create initial root metadata and RSTUF config.                         │
    │ import-artifacts         Import artifacts to RSTUF from exported CSV file.                                            │
    │ metadata                 Metadata management.                                                                         │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯


.. rstuf-cli-admin-ceremony

Ceremony (``ceremony``)
-----------------------

The Repository Service for TUF Metadata uses the following Roles: ``root``, ``timestamp``,
``snapshot``, ``targets``, and ``bins`` to build the Repository
Metadata (for more details, check out TUF Specification and PEP 458).

The Ceremony is a complex process that Repository Service for TUF CLI tries to simplify.
You can do the Ceremony offline. This means on a disconnected computer
(recommended once you will manage the keys).


.. code:: shell

    ❯ rstuf admin ceremony -h

    Usage: rstuf admin ceremony [OPTIONS]

    Bootstrap Ceremony to create initial root metadata and RSTUF config.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --save  -s  FILENAME  Write json result to FILENAME (default: 'ceremony-payload.json')                               │
    │ --help  -h            Show this message and exit.                                                                    │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

There are four steps in the ceremony.

.. note::

    We recommend running the ``rstuf admin ceremony`` to simulate and check
    the details of the instructions. It is more detailed.


.. rstuf-cli-admin-metadata

Metadata Management (``metadata``)
----------------------------------

.. code::

    ❯ rstuf admin metadata

    Usage: rstuf admin metadata [OPTIONS] COMMAND [ARGS]...

    Metadata management.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --help  -h    Show this message and exit.                                                                            │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ sign               Add one signature to root metadata.                                                               │
    │ update             Update root metadata and bump version.                                                            │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯


.. rstuf-cli-admin-metadata-sign

sign (``sign``)
...............

.. warning:: Do not share the private key.

.. code:: shell


    ❯ rstuf admin metadata sign -h

    Usage: rstuf admin metadata sign [OPTIONS] ROOT_IN [PREV_ROOT_IN]

    Add one signature to root metadata.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --save  -s  FILENAME  Write json result to FILENAME (default: 'sign-payload.json')                                   │
    │ --help  -h            Show this message and exit.                                                                    │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯



.. rstuf-cli-artifact

Artifact Management (``artifact``)
==================================

Manages artifacts using the RSTUF REST API.

.. code::

    ❯ rstuf artifact

    Usage: rstuf artifact [OPTIONS] COMMAND [ARGS]...

    Artifact Management Commands

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │ --help          -h    Show this message and exit.                                                │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

    ╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
    │ add          Add artifacts to the TUF metadata.                                                  │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

.. rstuf-cli-artifact-add

Artifact Addition (``add``)
---------------------------

This command adds the provided artifact to the TUF Metadata using the RSTUF REST API.

.. code::

    ❯ rstuf artifact add --help

    Usage: rstuf artifact add [OPTIONS] FILEPATH

    Add artifacts to the TUF metadata.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │ --path  -p  TEXT  A custom path (`TARGETPATH`) for the file, defined in the metadata. [required] │
    │ --help          -h    Show this message and exit.                                                │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

.. rstuf-cli-artifact-download

Artifact Download (``download``)
--------------------------------

This command allows downloading an artifact from a provided repository using the RSTUF REST API.

.. code::

    > rstuf artifact download --help

    Usage: rstuf artifact download [OPTIONS] ARTIFACT_NAME

    Downloads an artifact using TUF metadata from a given artifacts URL.
    Note: all options for this command can be configured.
    Read 'rstuf artifact repository' documentation for more information.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │ --root              -r  TEXT  A metadata URL to the initial trusted root or a local file.        │
    │ --metadata-url      -m  TEXT  TUF Metadata repository URL.                                       │
    │ --artifacts-url     -a  TEXT  An artifacts base URL to fetch from.                               │
    │ --hash-prefix       -p        A flag to prefix an artifact with a hash.                          │
    │ --directory-prefix  -P  TEXT  A prefix for the download dir.                                     │
    │ --help              -h        Show this message and exit.                                        │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

.. rstuf-cli-artifact-repository

Artifact Repository (``repository``)
------------------------------------

This command provides artifact repository management for the RSTUF repository config.

.. code::

    ❯ rstuf artifact repository --help

    Usage: rstuf artifact repository [OPTIONS] COMMAND [ARGS]...

    Repository management.

    ╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --help  -h    Show this message and exit.                                                                                                                                 │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ delete                           Delete a repository.                                                                                                                       │
    │ add                              Add a new repository.                                                                                                                    │
    │ show                             List configured repositories.                                                                                                            │
    │ update                           Update repository.                                                                                                                       │
    │ set                              Switch current repository.                                                                                                               │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

.. code::

    ❯ rstuf artifact repository delete --help

    Usage: rstuf artifact repository delete [OPTIONS] REPOSITORY

    Delete a repository.

.. code::

    ❯ rstuf artifact repository add --help

    Usage: rstuf artifact repository add [OPTIONS]

    Add a new repository.

    ╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ *  --name           -n  TEXT  The repository name. [required]                                                                                                               │
    │ *  --root           -r  TEXT  The metadata URL to the initial trusted root or a local file. [required]                                                                      │
    │ *  --metadata-url   -m  TEXT  TUF Metadata repository URL. [required]                                                                                                     │
    │ *  --artifacts-url  -a  TEXT  The artifacts base URL to fetch from. [required]                                                                                             │
    │    --hash-prefix    -p        Whether to add a hash prefix to artifact names.                                                                                             │
    │    --help           -h        Show this message and exit.                                                                                                                 │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

.. code::

    ❯ rstuf artifact repository show --help

    Usage: rstuf artifact repository show [OPTIONS] [REPOSITORY]

    List configured repositories.

.. code::

    ❯ rstuf artifact repository update --help

    Usage: rstuf artifact repository update [OPTIONS] REPOSITORY

    Update repository.

    ╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │ --root           -r  TEXT  The metadata URL to the initial trusted root or a local file.                                                                                    │
    │ --metadata-url   -m  TEXT  TUF Metadata repository URL.                                                                                                                   │
    │ --artifacts-url  -a  TEXT  The artifacts base URL to fetch from.                                                                                                          │
    │ --hash-prefix    -p        Whether to add a hash prefix to artifact names.                                                                                                                                 │
    │ --help           -h        Show this message and exit.                                                                                                                    │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

.. code::

    ❯ rstuf artifact repository set --help

    Usage: rstuf artifact repository set [OPTIONS] REPOSITORY

    Switch current repository.


.. rstuf-cli-task

Task Management (``task``)
==================================

Manages tasks using the RSTUF REST API.

.. code::

    ❯ rstuf task

    Usage: rstuf task [OPTIONS] COMMAND [ARGS]...

    Task Management Commands

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │ --help          -h    Show this message and exit.                                                │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

    ╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
    │ info          Retrieve task state.                                                               │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

.. rstuf-cli-task-info

Task Information (``info``)
---------------------------

This command retrieves the task state of the given task ID using the RSTUF REST API.

.. code::

    ❯ rstuf task info --help

    Usage: rstuf task info [OPTIONS] TASK_ID

    Retrieve task state.

    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │ --api-server      TEXT  RSTUF API URL, i.e., http://127.0.0.1                                    │
    │ --help          -h    Show this message and exit.                                                │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

