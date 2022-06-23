from kaprien.admin.ceremony import ceremony  # type: ignore


class TestCeremonyGroupCLI:
    def test_ceremony(self, client):
        test_result = client.invoke(ceremony)
        assert test_result.exit_code == 1
        assert "Metadata Initialization Ceremony" in test_result.output

    def test_ceremony_start_no(self, client):
        test_result = client.invoke(ceremony, input="n\n")
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_yes(self, client):
        test_result = client.invoke(ceremony, input="y\n")
        assert "STEP 1: " in test_result.output
        assert test_result.exit_code == 1

    # TODO: test multiple input sequence
    # def test_ceremony_start_yes_skip(self, client):
    #     input_sequence = "y\nskip\n"
    #     test_result = client.invoke(ceremony,  input=input_sequence)
    #     breakpoint()
    #     assert "STEP 2: " in test_result.output
    #     assert test_result.exit_code == 1

    # @mock.patch("kaprien.ceremony._load_key")
    # def test_ceremony_start_yes_skip_step_2_all_keys_ok(
    #     self, mock__load_key, client
    # ):
    #     input_sequence = (
    #         "y"  # Start the Ceremony
    #         "\nskip"  # Skip STEP 1
    #         "\ny"  # Start loading keys
    #         "\njimi_hendrix.key"  # keys...
    #         "\nHey_Joe"
    #         "\njanis_joplin.key"
    #         "\nHey_Joe"
    #         "\nsnapshot.key"
    #         "\nsnapshot_pass"
    #         "\ntimestamp.key"
    #         "\ntimestamp_pass"
    #         "\njoe_cocker.key"
    #         "\nLittle_Help_Hrom_My_Friends"
    #         "\nbins.key"
    #         "\nbins_pass"
    #         "\ny"  # root OK
    #         "\ny"  # targets OK
    #         "\ny"  # snapshot OK
    #         "\ny"  # timestamp OK
    #         "\ny"  # bin OK
    #         "\ny"  # bins OK
    #     )

    #     mock__load_key.side_effect = [
    #         Key({"keyid": "fake_key_id_1"}),
    #         Key({"keyid": "fake_key_id_2"}),
    #         Key({"keyid": "fake_key_id_3"}),
    #         Key({"keyid": "fake_key_id_4"}),
    #         Key({"keyid": "fake_key_id_5"}),
    #         Key({"keyid": "fake_key_id_6"}),
    #     ]
    #     test_result = client.invoke(ceremony,  input_sequence)
    #     assert test_result.exit_code == 0
    #     assert "Role: root" in test_result.output
    #     assert "Number of Keys: 1" in test_result.output
    #     assert "Threshold: 1" in test_result.output
    #     assert "Keys Type: offline" in test_result.output
    #     assert "jimi_hendrix.key" in test_result.output
    #     assert "fake_key_id_1" in test_result.output
    #     assert "Role: targets" in test_result.output
    #     assert "Number of Keys: 1" in test_result.output
    #     assert "janis_joplin.key" in test_result.output
    #     assert "fake_key_id_2" in test_result.output
    #     assert "Role: snapshot" in test_result.output
    #     assert "Keys Type: online" in test_result.output
    #     assert "fake_key_id_3" in test_result.output
    #     assert "Role: timestamp" in test_result.output
    #     assert "timestamp.key" in test_result.output
    #     assert "fake_key_id_4" in test_result.output
    #     assert "joe_cocker.key" in test_result.output
    #     assert "fake_key_id_5" in test_result.output
    #     assert "bins.key" in test_result.output
    #     assert "fake_key_id_6" in test_result.output
    #     # passwords not shown in output
    #     assert "Hey_Joe" not in test_result.output
    #     assert "snapshot_pass" not in test_result.output
    #     assert "timestamp_pass" not in test_result.output
    #     assert "Little_Help_Hrom_My_Friends" not in test_result.output
    #     assert "bins_pass" not in test_result.output
