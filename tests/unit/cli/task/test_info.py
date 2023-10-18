# SPDX-License-Identifier: MIT

import pretend  # type: ignore

from repository_service_tuf.cli.task import info


class TestTaskInfoInteraction:
    """Test the Task Info Interaction"""

    def test_info(self, client, test_context):
        """
        Test that the task info command works as expected given the
        expected arguments/options in the CLI.
        """

        task_id = "0123456789"

        input = [
            task_id,
        ]

        info.task_status = pretend.call_recorder(lambda *a, **kw: "123")

        result = client.invoke(info.info, input, obj=test_context)

        assert info.task_status.calls == [
            pretend.call(
                task_id=task_id,
                settings=test_context["settings"],
                title="Task status:",
            )
        ]

        assert result.exit_code == 0, result.output
