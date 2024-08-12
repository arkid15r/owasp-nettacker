import ssl
from unittest.mock import patch

from core.lib.ssl import (
    SslEngine,
    SslLibrary,
    create_tcp_socket,
    is_weak_hash_algo,
    is_weak_ssl_version,
    is_weak_cipher_suite,
)

from tests.common import TestCase, MockConnectionObject, Mockx509Object


class Responses:
    ssl_version_scan = {
        "ssl_version": ["TLSv1"],
        "weak_version": True,
        "ssl_flag": True,
    }

    ssl_certificate_expired = {
        "expired": True,
        "expiration_date": "07/12/2023",
        "not_activated": False,
        "activation_date": "07/12/2023",
        "expiring_soon": True,
        "ssl_flag": True,
    }

    ssl_certificate_deactivated = {
        "expired": False,
        "expiration_date": "07/12/2100",
        "expiring_soon": False,
        "not_activated": True,
        "activation_date": "07/12/2100",
        "ssl_flag": True,
    }

    ssl_off = {"ssl_flag": False}


class Substeps:
    ssl_version_scan = {
        "method": "ssl_version_and_cipher_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "grouped_conditions": {
                    "condition_type": "and",
                    "conditions": {
                        "weak_version": {"reverse": False},
                        "ssl_version": {"reverse": False},
                    },
                }
            },
        },
    }

    ssl_expired_certificate_scan = {
        "method": "ssl_certificate_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "grouped_conditions_1": {
                    "condition_type": "and",
                    "conditions": {
                        "expired": {"reverse": False},
                        "expiration_date": {"reverse": False},
                    },
                },
                "grouped_conditions_2": {
                    "condition_type": "and",
                    "conditions": {
                        "expiring_soon": {"reverse": False},
                        "expiration_date": {"reverse": False},
                    },
                },
                "grouped_conditions_3": {
                    "condition_type": "and",
                    "conditions": {
                        "not_activated": {"reverse": False},
                        "activation_date": {"reverse": False},
                    },
                },
            },
        },
    }


class TestSocketMethod(TestCase):
    @patch("socket.socket")
    @patch("ssl.wrap_socket")
    def test_create_tcp_socket(self, mock_wrap, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        create_tcp_socket(HOST, PORT, TIMEOUT)
        socket_instance = mock_socket.return_value
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))
        mock_wrap.assert_called_with(socket_instance)

    @patch("core.lib.ssl.is_weak_cipher_suite")
    @patch("core.lib.ssl.is_weak_ssl_version")
    @patch("core.lib.ssl.create_tcp_socket")
    def test_ssl_version_and_cipher_scan(self, mock_connection, mock_ssl_check, mock_cipher_check):
        library = SslLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_ssl_check.return_value = ("TLSv1.3", False)
        mock_cipher_check.return_value = (["HIGH"], False)
        self.assertEqual(
            library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": False,
                "ssl_version": "TLSv1.3",
                "peer_name": "example.com",
                "cipher_suite": ["HIGH"],
                "weak_cipher_suite": False,
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.1"), True)
        mock_ssl_check.return_value = ("TLSv1.1", True)
        mock_cipher_check.return_value = (["LOW"], True)
        self.assertEqual(
            library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": True,
                "ssl_version": "TLSv1.1",
                "peer_name": "example.com",
                "cipher_suite": ["LOW"],
                "weak_cipher_suite": True,
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST), False)
        self.assertEqual(
            library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": False,
                "service": "http",
                "peer_name": "example.com",
            },
        )

    @patch("core.lib.ssl.create_tcp_socket")
    @patch("core.lib.ssl.is_weak_hash_algo")
    @patch("core.lib.ssl.crypto.load_certificate")
    @patch("core.lib.ssl.ssl.get_server_certificate")
    def test_ssl_certificate_scan(
        self, mock_certificate, mock_x509, mock_hash_check, mock_connection
    ):
        library = SslLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_hash_check.return_value = False
        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=False,
            issuer="test_issuer",
            subject="test_subject",
            signing_algo="test_algo",
            expire_date=b"21001207153045Z",
            activation_date=b"20231207153045Z",
        )

        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": False,
                "ssl_flag": True,
                "service": "http",
                "self_signed": False,
                "expiring_soon": False,
                "expiration_date": "07/12/2100",
                "not_activated": False,
                "activation_date": "07/12/2023",
                "signing_algo": "test_algo",
                "weak_signing_algo": False,
                "peer_name": "example.com",
            },
        )

        mock_hash_check.return_value = True
        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=True,
            issuer="test_issuer_subject",
            subject="test_issuer_subject",
            signing_algo="test_algo",
            expire_date=b"21001207153045Z",
            activation_date=b"21001207153045Z",
        )
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": True,
                "ssl_flag": True,
                "service": "http",
                "self_signed": True,
                "expiring_soon": False,
                "expiration_date": "07/12/2100",
                "not_activated": True,
                "activation_date": "07/12/2100",
                "signing_algo": "test_algo",
                "weak_signing_algo": True,
                "peer_name": "example.com",
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST), False)
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "service": "http",
                "ssl_flag": False,
                "peer_name": "example.com",
            },
        )
        mock_certificate.assert_called_with((HOST, PORT))

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_is_weak_cipher_suite(self, mock_context, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        socket_instance = mock_socket.return_value
        context_instance = mock_context.return_value
        cipher_list = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "EXP",
            "eNULL",
            "aNULL",
            "RC4",
            "DES",
            "MD5",
            "SHA1",
            "DH",
            "ADH",
            "DHE",
            "ECDH",
            "ECDHE",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3",
        ]
        self.assertEqual(is_weak_cipher_suite(HOST, PORT, TIMEOUT), (cipher_list, True))
        context_instance.wrap_socket.assert_called_with(socket_instance, server_hostname=HOST)
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))

        context_instance.wrap_socket.side_effect = ssl.SSLError
        self.assertEqual(is_weak_cipher_suite(HOST, PORT, TIMEOUT), ([], False))

    def test_is_weak_hash_algo(self):
        for algo in ("md2", "md4", "md5", "sha1"):
            self.assertTrue(is_weak_hash_algo(algo))
        self.assertFalse(is_weak_hash_algo("test_aglo"))

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_is_weak_ssl_version(self, mock_context, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        socket_instance = mock_socket.return_value
        context_instance = mock_context.return_value

        context_instance.wrap_socket.return_value = MockConnectionObject(HOST, "TLSv1.3")
        self.assertEqual(
            is_weak_ssl_version(HOST, PORT, TIMEOUT),
            (["TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3"], False),
        )

        context_instance.wrap_socket.return_value = MockConnectionObject(HOST, "TLSv1.1")
        self.assertEqual(
            is_weak_ssl_version(HOST, PORT, TIMEOUT),
            (["TLSv1.1", "TLSv1.1", "TLSv1.1", "TLSv1.1"], True),
        )

        context_instance.wrap_socket.side_effect = ssl.SSLError
        self.assertEqual(is_weak_ssl_version(HOST, PORT, TIMEOUT), ([], True))

        context_instance.wrap_socket.side_effect = ConnectionRefusedError
        self.assertEqual(is_weak_ssl_version(HOST, PORT, TIMEOUT), ([], True))

        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))

        context_instance.wrap_socket.assert_called_with(socket_instance, server_hostname=HOST)

    def test_response_conditions_matched(self):
        # tests the response conditions matched for different scan methods
        engine = SslEngine()
        Substep = Substeps()
        Response = Responses()

        # ssl_certificate_scan_expired
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.ssl_expired_certificate_scan, Response.ssl_certificate_expired
            ),
            {"expired": True, "expiration_date": "07/12/2023", "expiring_soon": True},
        )
        # ssl_certificate_scan_not_activated
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.ssl_expired_certificate_scan,
                Response.ssl_certificate_deactivated,
            ),
            {"not_activated": True, "activation_date": "07/12/2100"},
        )

        # ssl_version_scan
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.ssl_version_scan, Response.ssl_version_scan
            ),
            {"weak_version": True, "ssl_version": ["TLSv1"]},
        )

        # ssl_* scans with ssl_flag = False
        self.assertEqual(
            engine.response_conditions_matched(Substep.ssl_version_scan, Response.ssl_off), []
        )

        # * scans with response None i.e. TCP connection failed(None)
        self.assertEqual(engine.response_conditions_matched(Substep.ssl_version_scan, None), [])
