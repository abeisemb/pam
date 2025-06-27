"""
PAM Test Cases

:requirement: pam
:casecomponent: pam
:subsystemteam: sst_idm_sssd
:status: approved
"""

import pytest
import subprocess
import os
import time
from sssd.testlib.common.utils import SSHClient


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_chkpwd_onlyroot(self, multihost):
        """ This test checks whether unix_chkpwd doesn't allow other user's password guessing.

        :id: d3e88514-859a-11ec-bd05-845cf3eff344
        """
        execute_cmd(multihost, "yum -y install expect shadow-utils sed grubby")
        username1 = "testuser1"
        username2 = "testuser2"
        password = "tYnef*9sX"
        file_location1 = "/multihost_test/bz_automation/script/chkpwd-onlyroot_1.sh"
        file_location2 = "/multihost_test/bz_automation/script/chkpwd-onlyroot_2.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location1, '/tmp/chkpwd-onlyroot_1.sh')
        multihost.client[0].transport.put_file(os.getcwd() + file_location2, '/tmp/chkpwd-onlyroot_2.sh')
        execute_cmd(multihost, f"useradd {username1}")
        execute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_1.sh {username1} {password}")
        execute_cmd(multihost, f'useradd {username2}')
        execute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_1.sh {username2} {password}")
        execute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username1} {username1} {password}")
        execute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username2} {username2} {password}")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username1} {username2} {password}")
        execute_cmd(multihost, f"userdel -rf {username1}")
        execute_cmd(multihost, f"userdel -rf {username2}")

    def test_bz675835(self, multihost, bkp_pam_config, create_localusers):
        """bz675835-RFE-Please-support-nodefgroup-in-pam-access

        :id: a9c10cf2-85c7-11ec-9ed5-845cf3eff344
        """
        execute_cmd(multihost, "yum install -y expect")
        execute_cmd(multihost, "yum install -y openssh")
        file_location1 = "/multihost_test/bz_automation/script/bz675835.sh"
        file_location2 = "/multihost_test/bz_automation/script/bz675835_1.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location1, '/tmp/bz675835.sh')
        multihost.client[0].transport.put_file(os.getcwd() + file_location2, '/tmp/bz675835_1.sh')
        execute_cmd(multihost, "sed -i '/^account.*/i account required pam_access.so nodefgroup' /etc/pam.d/sshd")
        execute_cmd(multihost, "echo 'account required pam_access.so nodefgroup' >> /etc/pam.d/sshd")
        execute_cmd(multihost, "usermod -a -G testgroup local_anuj")
        execute_cmd(multihost, "usermod -a -G testgroup pamtest1")
        execute_cmd(multihost, "sh /tmp/bz675835_1.sh")
        execute_cmd(multihost, 'echo "-:testgroup:ALL" > /etc/security/access.conf')
        execute_cmd(multihost, "sh /tmp/bz675835.sh local_anuj x")
        execute_cmd(multihost, "sh /tmp/bz675835.sh pamtest1 x")
        execute_cmd(multihost, 'echo "-:(testgroup):ALL" > /etc/security/access.conf')
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/bz675835.sh local_anuj x")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/bz675835.sh pamtest1 x")

    def test_1949137(self, multihost, bkp_pam_config, create_system_user, create_localusers):
        """pam_usertype has flawed logic for system accounts.

        :id: fe3e1048-9483-11ec-b9bb-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1949137
        """
        file_location1 = "/multihost_test/bz_automation/script/system-auth"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location1,
                                               '/etc/pam.d/system-auth')
        ssh1 = SSHClient(multihost.client[0].ip, username="local_anuj", password="password123")
        (result, result1, exit_status) = ssh1.execute_cmd('su - systest', stdin="password123")
        assert "Password: su: Authentication failure" in result1.readlines()[0]

    def test_2014458(self, multihost, create_localusers):
        """Please backport checking multiple motd_pam paths from 1.4.0 to RHEL 8

        :id: 2c54e376-d5e8-11ec-87cb-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2014458
        """
        file_location = '/multihost_test/bz_automation/script/authentication.sh'
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/authentication.sh')
        execute_cmd(multihost, f"chmod 755 /tmp/authentication.sh")
        multihost.client[0].run_command("mkdir /run/motd.d", raiseonerr=False)
        message = "Welcome to this system"
        execute_cmd(multihost, f'echo "{message}" > /run/motd.d/welcome')
        execute_cmd(multihost, "restorecon -Rv /run/motd.d")
        cmd = execute_cmd(multihost, "sh /tmp/authentication.sh")
        assert message in cmd.stdout_text
        execute_cmd(multihost, 'rm -vf /run/motd.d/welcome')
        execute_cmd(multihost, 'rm -vf /tmp/authentication.sh')

    def test_pam_unix(self, multihost):
        """pam authentication from root/user

        :id: da0bf07e-38f6-11ed-93d7-845cf3eff344
        """
        PASSWORD = "TestPassword"
        MD5PASS = "'$1$6fB26h/v$Ho7JpVkiq6Qd5GfZv0qDR/'"
        CRYPTPASS = 'C/Zxkuzt3sBiI'
        TmpDir = "/tmp/tmp.N9BJmxhaTQ"
        client = multihost.client[0]
        execute_cmd(multihost, f"rm -vfr {TmpDir}")
        execute_cmd(multihost, f"mkdir {TmpDir}")
        execute_cmd(multihost, f'chmod a+rwx {TmpDir}')
        execute_cmd(multihost, f"pushd {TmpDir}")
        execute_cmd(multihost, "useradd testUser")
        execute_cmd(multihost, f"echo {PASSWORD} | passwd --stdin testUser")
        CMD_PAMTEST = f"{TmpDir}/pamtest"
        for f_file in ["pamtest.c", "pamtest"]:
            file_location = f"/multihost_test/bz_automation/script/{f_file}"
            client.transport.put_file(os.getcwd()
                                      + file_location,
                                      f'/tmp/{f_file}')
        execute_cmd(multihost, f"gcc -Wall -g -o {CMD_PAMTEST} /tmp/pamtest.c -lpam -ldl")
        execute_cmd(multihost, "export LANG=C")
        execute_cmd(multihost, "ls -la")
        execute_cmd(multihost, ">/etc/pam.d/pamtest")
        execute_cmd(multihost, "cp -vf /tmp/pamtest /etc/pam.d/pamtest")
        for user in ['root', 'testUser']:
            execute_cmd(multihost, f"usermod -p {MD5PASS} testUser")
            execute_cmd(multihost, f'su - {user} -c {CMD_PAMTEST}')
            execute_cmd(multihost, f"usermod -p {CRYPTPASS} testUser")
            execute_cmd(multihost, f'su - {user} -c {CMD_PAMTEST}')
            for password in ["'!!'", "'*'", "'xy'", "'$1'"]:
                execute_cmd(multihost, f"usermod -p {password} testUser")
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, f'su - {user} -c {CMD_PAMTEST}')
        execute_cmd(multihost, "userdel -rf testUser")

    def test_19810(self, multihost, bkp_pam_config, create_localusers):
        """Faillock does not create tallydir

        :id: 2533f790-abc4-11ee-bde9-845cf3eff344
        :bugzilla: https://issues.redhat.com/browse/RHEL-19810
        :steps:
          1. Set dir option in /etc/security/faillock.conf with non-existence folder
          2. Run "faillock" at command line.
        :expectedresults:
          1. Modification Should succeed
          2. tallydir is created automatically
        """
        client = multihost.client[0]
        client.run_command("rm -vfr /tmp/anuj", raiseonerr=False)
        client.run_command("echo 'dir = /tmp/anuj' >> /etc/security/faillock.conf")
        client.run_command("sed -i '5i auth [default=die] pam_faillock.so authfail' /etc/pam.d/system-auth")
        client.run_command("sed -i '6i auth sufficient pam_faillock.so authsucc' /etc/pam.d/system-auth")
        ssh1 = SSHClient(multihost.client[0].ip, username="local_anuj", password="password123")
        (result, result1, exit_status) = ssh1.execute_cmd('su - local_anuj', stdin="password123")
        client.run_command("faillock")
        assert "Password: su: Authentication failure" not in result1.readlines()[0]

    def test_16727(self, multihost, bkp_pam_config, create_localusers):
        """PAM can't identify the user when running from external host

        :id: ae78e4d6-ba95-11ee-8362-845cf3eff344
        :bugzilla: https://issues.redhat.com/browse/RHEL-16727
        :steps:
          1. Create "local_anuj" user and set password
          2. Add user to testgroup group
          3. Configure "local_anuj" user in sudoers to be able to sudo without password
          4. Configure /etc/pam.d/sudo
          5. Configure /etc/pam.d/su
          6. ssh into the machine as "local_anuj" and issue "sudo su"
          7. Check /var/log/secure and make sure that the log is present

        :expectedresults:
          1. User should be created
          2. User should be added to group
          3. This line should be added: testuser        ALL=(ALL)    NOPASSWD: ALL
          4. Comment out : "account    include      system-auth" and replace with:
            account    sufficient   pam_wheel.so trust group=users debug
          5. This line should be added: account    sufficient
            pam_wheel.so trust group=users debug
          6. Ssh should success
          7. This line should present :
            su[2281]: pam_wheel(su:account): Access granted to 'testuser' for 'root'
        """
        client = multihost.client[0]
        client.run_command("usermod -G testgroup local_anuj")
        client.run_command("echo 'local_anuj        ALL=(ALL)    NOPASSWD: ALL' >> /etc/sudoers")
        client.run_command("sed -i 's/^account.*/account    sufficient   "
                           "pam_wheel.so trust group=testgroup debug/g' /etc/pam.d/sudo")
        client.run_command("sed -i '/account/iaccount    sufficient   "
                           "pam_wheel.so trust group=testgroup debug' /etc/pam.d/su")
        client.run_command("> /var/log/secure")
        time.sleep(1)
        ssh1 = SSHClient(multihost.client[0].ip, username="local_anuj", password="password123")
        ssh1.execute_cmd('sudo su -c "ls /root/"')
        time.sleep(1)
        assert "Access granted to 'local_anuj' for 'root'" \
               in client.run_command("cat /var/log/secure").stdout_text
