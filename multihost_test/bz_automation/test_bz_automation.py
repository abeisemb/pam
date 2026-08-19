"""
PAM Test Cases

:requirement: pam
:casecomponent: pam
:subsystemteam: sst_idm_sssd
:status: approved
"""

import pytest
from sssd.testlib.common.utils import SSHClient


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
@pytest.mark.usefixtures('unlimited_ssh')
class TestPamBz(object):
    def test_unlimited(self, multihost):
        """For nofile, a value of "unlimited" should be allowed.

        :id: 54d940a6-540d-11ec-9a01-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1989900
        """
        execute_cmd(multihost, "su -c 'id' anuj_test > /tmp/anuj")
        cmd = execute_cmd(multihost, "cat /tmp/anuj")
        for id_id in ['uid=', 'gid=', 'groups=', 'anuj_test']:
            assert id_id in cmd.stdout_text

    def test_unlimited_ssh(self, multihost):
        """For nofile, a value of "unlimited" should be allowed.

        :id: 54d940a6-540d-11ec-9a01-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1989900
        """
        user = "anuj_test"
        client_e = multihost.client[0].ip
        ssh1 = SSHClient(client_e, username=user, password="password123")
        (result1, result2, result3) =  ssh1.execute_cmd("id")
        ssh1.close()
        result = result1.readlines()
        for id_id in ['uid=', 'gid=', 'groups=', 'anuj_test']:
            assert id_id in result[0]
