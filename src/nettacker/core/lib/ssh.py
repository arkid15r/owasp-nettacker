import logging

from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError, SSHException

from nettacker.core.lib.base import BaseEngine, BaseLibrary

logging.getLogger("paramiko.transport").disabled = True


class SshLibrary(BaseLibrary):
    def brute_force(self, *args, **kwargs):
        connection = SSHClient()
        connection.set_missing_host_key_policy(AutoAddPolicy())
        connection.connect(
            **{
                "hostname": kwargs["host"],
                "port": kwargs["port"],
                "username": kwargs["username"],
                "password": kwargs["password"],
                "timeout": kwargs["timeout"],
            }
        )
        connection.close()

        return {
            "host": kwargs["host"],
            "port": kwargs["port"],
            "username": kwargs["username"],
            "password": kwargs["password"],
        }


class SshEngine(BaseEngine):
    library = SshLibrary
