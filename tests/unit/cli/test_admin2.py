class TestSign:
    def test_sign_v1(self):
        """Sign root v1, with 2/2 keys.

        Enter path to root to sign: tests/files/root/v1.json
        need 2 signature(s) from any of {'50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3', 'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc'}
        Review? [y/n]: n
        Sign? [y/n]: y
        Choose key [50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3
        Enter path to encrypted local private key: tests/files/pem/ec
        Enter password: hunter2
        Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3
        need 1 signature(s) from any of {'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc'}
        Sign? [y/n]: y
        Choose key [c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc
        Enter path to encrypted local private key: tests/files/pem/ed
        Enter password: hunter2
        Signed with key c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc
        Metadata fully signed.
        Save? [y/n]: n
        Bye.
        """
        # TODO: write test

    def test_sign_v2(self):
        """Sign root v2, with 2/2 keys from old root and 2/2 from new, where
        1 key is in both old and new (needs 3 signatures in total).

        Enter path to root to sign: tests/files/root/v2.json
        Enter path to previous root: tests/files/root/v1.json
        need 2 signature(s) from any of {'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc', '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3'}
        need 2 signature(s) from any of {'2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241', '50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3'}
        Review? [y/n]: n
        Sign? [y/n]: y
        Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241/50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133
        b47fc33df03d4070a7e1e9cc]: 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3
        Enter path to encrypted local private key: tests/files/pem/ec
        Enter password: hunter2
        Signed with key 50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3
        need 1 signature(s) from any of {'c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc'}
        need 1 signature(s) from any of {'2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241'}
        Sign? [y/n]: y
        Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241/c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc]: c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc
        Enter path to encrypted local private key: tests/files/pem/ed
        Enter password: hunter2
        Signed with key c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc
        need 1 signature(s) from any of {'2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241'}
        Sign? [y/n]: y
        Choose key [2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241]: 2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241
        Enter path to encrypted local private key: tests/files/pem/rsa
        Enter password: hunter2
        Signed with key 2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241
        Metadata fully signed.
        Save? [y/n]: n
        Bye.
        """
        # TODO: write test
