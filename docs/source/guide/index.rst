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

    ❯ rstuf
                                                                                                                                                 
     Usage: rstuf [OPTIONS] COMMAND [ARGS]...                                                                                                  
                                                                                                                                                 
     Repository Service for TUF Command Line Interface (CLI).                                                                                        
                                                                                                                                                 
    ╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  --config  -c  TEXT  Repository Service for TUF config file                                                                                   │
    │  --help    -h        Show this message and exit.                                                                                          │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  admin  Administrative Commands                                                                                                           │
    ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    
Administration (``admin``)
==========================

It executes administrative commands to the Repository Service for TUF.

.. code:: shell

    ❯ rstuf admin

    Usage: rstuf admin [OPTIONS] COMMAND [ARGS]...

    Administrative Commands

    ╭─ Options ────────────────────────────────────────────────────────────────────────────╮
    │  --help  -h    Show this message and exit.                                           │
    ╰──────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ───────────────────────────────────────────────────────────────────────────╮
    │  ceremony  Start a new Metadata Ceremony.                                            │
    │  login     Login to Repository Service for TUF (API).                                            │
    │  token     Token Management.                                                         │
    ╰──────────────────────────────────────────────────────────────────────────────────────╯


Login to Server (``login``)
---------------------------

This command will log in to Repository Service for TUF and give you a token to run other commands
such as Ceremony, Token Generation, etc.

.. code:: shell

    ❯ rstuf admin login
    ╔══════════════════════════════════════════════════════════════════════════════════════╗
    ║                     Login to Repository Service for TUF                              ║
    ╚══════════════════════════════════════════════════════════════════════════════════════╝

    ┌──────────────────────────────────────────────────────────────────────────────────────┐
    │         The server and token will generate a token and it will be                    │
    │         stored in /Users/kairoaraujo/.rstuf.ini                                      │
    └──────────────────────────────────────────────────────────────────────────────────────┘

    Server Address: http://192.168.1.199
    Username (admin): admin
    Password:
    Expire (in hours): 2
    Token stored in /Users/kairoaraujo/.repository_service_tuf.ini

    Login successful.


Ceremony (``ceremony``)
-----------------------

The Repository Service for TUF Metadata uses the following Roles: ``root``, ``timestamp``,
``snapshot``, ``targets``, and ``bins`` to build the Repository
Metadata (for more details, check out TUF Specification and PEP 458).

The Ceremony is a complex process that Repository Service for TUF CLI tries to simplify.
You can do the Ceremony offline. This means on a disconnected computer
(recommended once you will manage the keys).


.. code:: shell

    ❯ rstuf admin ceremony --help
                                                                                                                            
    Usage: rstuf admin ceremony [OPTIONS]                                                                                  
                                                                                                                            
    Start a new Metadata Ceremony.                                                                                           
                                                                                                                            
    ╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  --bootstrap  -b        Bootstrap a Repository Service for TUF using the Repository Metadata after Ceremony     │
    │  --file       -f  TEXT  Generate specific JSON Payload compatible with Repository Service for TUF bootstrap     │
                              after Ceremony                                                                          │
    │                         [default: payload.json]                                                                 │
    │  --upload     -u        Upload existent payload 'file'. Requires '-b/--bootstrap'. Optional '-f/--file' to use  │
    │                         non default file.                                                                       │
    │  --save       -s        Save a copy of the metadata locally. This option saves the metadata files (json) in the │
    │                         'metadata' dir.                                                                         │
    │                         [default: False]                                                                        │
    │  --help       -h        Show this message and exit.                                                             │
    ╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

There are three steps in the Ceremony.

.. note::

    We recommend running the ``rstuf admin ceremony`` to simulate and check
    the details of the instructions. It is more detailed.


Step 1: Configure the Roles
...........................

.. code:: shell

    ❯ rstuf admin ceremony

    (...)
    Do you want start the ceremony? [y/n]: y
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                         STEP 1: Configure the Roles                          ║
    ╚══════════════════════════════════════════════════════════════════════════════╝

    The TUF roles support multiple keys and the threshold (quorum trust) defines
    the minimal number of keys required to take actions using a specific Role.

    Reference: TUF                                                                  

    What is the Metadata expiration for the root role?(Days) (365):
    What is the number of keys for the root role? (2):
    What is the key threshold for the root role signing? (1):

    What is the Metadata expiration for the targets role?(Days) (365):
    What is the number of keys for the targets role? (2):
    What is the key threshold for the targets role signing? (1):
    The role targets delegate trust for all target files to 'bin-n' roles based on file path hash prefixes,
    a.k.a hash bin delegation. See TUF TAP 15: https://github.com/theupdateframework/taps/blob/master/tap15.md
    You can also have a look at our example.
    Show example [y/n] (y): y

                                                Example:                                              

    The Organization Example (https://example.com) has all files downloaded /downloads path, meaning    
    https://example.com/downloads/.                                                                     

    Additionally, it has two sub-folders, productA and productB where the clients can find all files
    (i.e.: productA-v1.0.tar, productB-v1.0.tar), for productB it even has a sub-folder, updates where
    clients can find update files (i.e.: servicepack-1.tar, servicepack-2.tar).
    The organization has decided to use 8 hash bins. Target files will be uniformly distributed over
    8 bins whose names will be "1.bins-0.json", "1.bins-1.json", ... , "1.bins-7.json".

    Now imagine that the organization stores the following files:
    - https://example.com/downloads/productA/productA-v1.0.tar
    - https://example.com/downloads/productB/productB-v1.0.tar
    - https://example.com/downloads/productB/updates/servicepack-1.tar

    As we said the targets will be uniformly distributed over the 8 bins no matter if they are
    located in the same folder. In this example here is how they will be distributed:
    - "1.bins-4.json" will be responsible for file productA/productA-v1.0.tar
    - "1.bins-5.json" will be responsible for file productB/productB-v1.1.tar
    - "1.bins-1.json" will be responsible for file productB/updates/servicepack-1.tar

    How many hash bins do you want for targets? (8):

    What is the Base URL (i.e.: https://www.example.com/downloads/): https://www.example.com/downloads/

    What is the Metadata expiration for the snapshot role?(Days) (1):
    What is the number of keys for the snapshot role? (1):
    The threshold for snapshot is 1 (one) based on the number of keys (1).

    What is the Metadata expiration for timestamp role?(Days) (1):
    What is the number of keys for timestamp role? (1):
    The threshold for timestamp is 1 (one) based on the number of keys (1).

    What is the Metadata expiration for the bins role?(Days) (1):
    What is the number of keys for the bins role? (1):
    The threshold for bins is 1 (one) based on the number of keys (1).


1. root ``expiration``, ``number of keys``, and ``threshold``
2. targets ``expiration``, ``number of keys``, ``threshold``, the ``base URL``
   for the files (target files), and the ``number of hash bins``
3. snapshot ``expiration``, ``number of keys``, and ``threshold``
4. timestamp ``expiration``, ``number of keys``, and ``threshold``
5. bins ``expiration``, ``number of keys``, and ``threshold``

- ``expiration`` is the number of days in which the Metadata will expire
- ``number of keys`` Metadata will have
- ``threshold`` is the number of keys needed to sign the Metadata
- ``base URL`` for the artifacts, example: http://www.example.com/download/
- ``number of hash bins`` is the number of hash bins between 1 and 32. How many
  delegated roles (``bins-X``) will it create?

Step 2: Loading the Keys
........................

It is essential to define the Key Owners. There is a suggestion in the CLI.

The owners will need to be present to share the key and use their password to
load the keys.

.. code:: shell

    ╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║                                     STEP 2: Load roles keys                                      ║
    ╚══════════════════════════════════════════════════════════════════════════════════════════════════╝

    The keys must have a password and the file must be accessible.

    Depending on the Organization, each key has an owner. During the key loading process, it is
    important that the owner of the key inserts the password.

    The password or the key content is not shown on the screen.

    Ready to start loading the keys? Passwords will be required for keys [y/n]: y

    Enter 1/2 the root`s Key path: tests/files/JanisJoplin.key
    Enter 1/2 the root`s Key password:
    ✅ Key 1/2 Verified

    Enter 2/2 the root`s Key path: tests/files/JimiHendrix.key
    Enter 2/2 the root`s Key password:
    ✅ Key 2/2 Verified

    Enter 1/2 the targets`s Key path: tests/files/KurtCobain.key
    Enter 1/2 the targets`s Key password:
    ✅ Key 1/2 Verified

    Enter 2/2 the targets`s Key path: tests/files/ChrisCornel.key
    Enter 2/2 the targets`s Key password:
    ✅ Key 2/2 Verified

    Enter 1/1 the snapshot`s Key path: tests/files/snapshot1.key
    Enter 1/1 the snapshot`s Key password:
    ✅ Key 1/1 Verified

    Enter 1/1 the timestamp`s Key path: tests/files/timestamp1.key
    Enter 1/1 the timestamp`s Key password:
    ✅ Key 1/1 Verified

    Enter 1/1 the bins`s Key path: tests/files/bins1.key
    Enter 1/1 the bins`s Key password:
    ✅ Key 1/1 Verified


Step 3: Validate the information/settings
.........................................

After confirming all details, the initial payload for bootstrap will be
complete (without the offline keys).

.. code:: shell

    ╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║                                  STEP 3: Validate configuration                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════════════════════╝

    The information below is the configuration done in the preview steps. Check the number of keys, the
    threshold/quorum and type of key.
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃       ROLE SUMMARY        ┃                                 KEYS                                 ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
    │        Role: root         │                   ╷                                     ╷            │
    │     Number of Keys: 2     │              path │                 id                  │ verified   │
    │       Threshold: 1        │ ╶─────────────────┼─────────────────────────────────────┼──────────╴ │
    │    Keys Type: offline     │   JanisJoplin.key │ 1cebe343e35f0213f6136758e6c3a8f8e1… │    ✅      │
    │ Role Expiration: 365 days │   JimiHendrix.key │ 800dfb5a1982b82b7893e58035e19f414f… │    ✅      │
    │                           │                   ╵                                     ╵            │
    └───────────────────────────┴──────────────────────────────────────────────────────────────────────┘
    Configuration correct for root? [y/n]: y
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃              ROLE SUMMARY               ┃                          KEYS                          ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
    │              Role: targets              │                   ╷                       ╷            │
    │            Number of Keys: 2            │              path │          id           │ verified   │
    │              Threshold: 1               │ ╶─────────────────┼───────────────────────┼──────────╴ │
    │           Keys Type: offline            │    KurtCobain.key │ 208fc4139cf7482abbe8… │    ✅      │
    │        Role Expiration: 365 days        │   ChrisCornel.key │ c2e9ee4a292e5d08bc0d… │    ✅      │
    │                                         │                   ╵                       ╵            │
    │                                         │                                                        │
    │                                         │                                                        │
    │               DELEGATIONS               │                                                        │
    │             targets -> bins             │                                                        │
    │              Number bins: 8             │                                                                        │
    └─────────────────────────────────────────┴────────────────────────────────────────────────────────┘
    Configuration correct for targets? [y/n]: y
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃      ROLE SUMMARY       ┃                                  KEYS                                  ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
    │     Role: snapshot      │                 ╷                                         ╷            │
    │    Number of Keys: 1    │            path │                   id                    │ verified   │
    │      Threshold: 1       │ ╶───────────────┼─────────────────────────────────────────┼──────────╴ │
    │    Keys Type: online    │   snapshot1.key │ 139c406ac6150598fb9f7cafd1463bc07e0318… │    ✅      │
    │ Role Expiration: 1 days │                 ╵                                         ╵            │
    └─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
    Configuration correct for snapshot? [y/n]: y
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃      ROLE SUMMARY       ┃                                  KEYS                                  ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
    │     Role: timestamp     │                  ╷                                        ╷            │
    │    Number of Keys: 1    │             path │                   id                   │ verified   │
    │      Threshold: 1       │ ╶────────────────┼────────────────────────────────────────┼──────────╴ │
    │    Keys Type: online    │   timestamp1.key │ 19f5992640ab71f49fb64d5b5d198ee0115c3… │    ✅      │
    │ Role Expiration: 1 days │                  ╵                                        ╵            │
    └─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
    Configuration correct for timestamp? [y/n]: y
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃      ROLE SUMMARY       ┃                                  KEYS                                  ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
    │       Role: bins        │             ╷                                             ╷            │
    │    Number of Keys: 1    │        path │                     id                      │ verified   │
    │      Threshold: 1       │ ╶───────────┼─────────────────────────────────────────────┼──────────╴ │
    │    Keys Type: online    │   bins1.key │ 9b2a880bd470e8373e24efb0dc54df3909e180e445… │    ✅       │
    │ Role Expiration: 1 days │             ╵                                             ╵            │
    └─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
    Configuration correct for bins? [y/n]: y

Finishing
.........

If you choose ``-b/--bootstrap`` it will automatically send the bootstrap to
``repository-service-tuf-api``, no actions necessary.

If you did the ceremony in a disconnected computer:
Using another computer with access to ``repository-service-tuf-api``
1.  Get the generated ``payload.json`` (or the custom name you chose)
2.  Install ``repository-service-tuf``
3.  Run ``rstuf admin ceremony -b [-u filename]``

Token (``token``)
-----------------

Token Management

.. code:: shell

    ❯ rstuf admin token
                                                                                                                            
    Usage: rstuf admin token [OPTIONS] COMMAND [ARGS]...                                                                   
                                                                                                                            
    Token Management.                                                                                                        
                                                                                                                            
    ╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  --help  -h    Show this message and exit.                                                                             │
    ╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
    ╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  generate  Generate new token.                                                                                         │
    │  inspect   Show token information details.                                                                             │
    ╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

``generate``
............
Generate tokens to use in integrations.

.. code:: shell

    ❯ rstuf admin token generate -h
                                                                                                        
    Usage: rstuf admin token generate [OPTIONS]                                                      
                                                                                                        
    Generate a new token.
                                                                                                        
    ╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
    │     --expires  -e  INTEGER  Expires in hours. Default: 24 [default: 24]                          │
    │  *  --scope    -s  TEXT     Scope to grant. Multiple is accepted. Ex: -s write:targets -s        │
    │                             read:settings                                                         │
    │                             [required]                                                           │
    │     --help     -h           Show this message and exit.                                          │
    ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

Example of usage:

.. code:: shell

    ❯ rstuf admin token generate -s write:targets
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyX
        zFfNTNiYTY4MzAwNTk3NGY2NWIxMDQ5NzczMjIiwicGFzc3dvcmQiOiJiJyQyYiQxMiRxT0
        5NRjdRblI3NG0xbjdrZW1MdFJld05MVDN2elNFLndsRHowLzBIWTJFaGxpY05uaFgzdSci
        LCJzY29wZXMiOlsid3JpdGU6dGFyZ2V0cyJdLCJleHAiOjE2NjIyODExMDl9.ugwibyv8H
        -zVgGgRfliKgUgHZrZzeJDeAw9mQJrYLz8"
    }

This token can be used with GitHub Secrets, Jenkins Secrets, CircleCI, shell
script, etc

``inspect``
...........

Show token detailed information.

.. code:: shell

    ❯ rstuf admin token inspect -h
                                                                                                                            
    Usage: rstuf admin token inspect [OPTIONS] TOKEN                                                                       
                                                                                                                            
    Show token information details.                                                                                          
                                                                                                                            
    ╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
    │  --help  -h    Show this message and exit.                                                                             │
    ╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

    ❯ rstuf admin token inspect eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1...PDwwY
    {
    "data": {
        "scopes": [
        "write:targets"
        ],
        "expired": false,
        "expiration": "2022-09-04T08:42:44"
    },
    "message": "Token information"
    }