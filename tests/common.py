import unittest
from pathlib import Path

from conftest import nettacker_dir, tests_dir


class TestCase(unittest.TestCase):
    nettacker_path = Path(nettacker_dir)
    tests_path = Path(tests_dir)


class MockConnectionObject:
    def __init__(self, peername, version=None):
        self.Peername = peername
        self.Version = version

    def getpeername(self):
        return self.Peername

    def version(self):
        return self.Version


class Mockx509Object:
    def __init__(self, issuer, subject, is_expired, expire_date, activation_date, signing_algo):
        self.issuer = issuer
        self.subject = subject
        self.expired = is_expired
        self.expire_date = expire_date
        self.activation_date = activation_date
        self.signature_algorithm = signing_algo

    def get_issuer(self):
        return self.issuer

    def get_subject(self):
        return self.subject

    def has_expired(self):
        return self.expired

    def get_notAfter(self):
        return self.expire_date

    def get_notBefore(self):
        return self.activation_date

    def get_signature_algorithm(self):
        return self.signature_algorithm
