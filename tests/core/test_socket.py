from unittest.mock import patch

from core.lib.socket import create_tcp_socket, SocketLibrary, SocketEngine

from tests.common import TestCase


class MockConnectionObject:
    def __init__(self, peername, version=None):
        self.Peername = peername
        self.Version = version

    def getpeername(self):
        return self.Peername

    def version(self):
        return self.Version


class Mockx509Object:
    def __init__(self, issuer, subject, is_expired, expire_date, signing_algo):
        self.issuer = issuer
        self.subject = subject
        self.expired = is_expired
        self.expire_date = expire_date
        self.signature_algorithm = signing_algo

    def get_issuer(self):
        return self.issuer

    def get_subject(self):
        return self.subject

    def has_expired(self):
        return self.expired

    def get_notAfter(self):
        return self.expire_date

    def get_signature_algorithm(self):
        return self.signature_algorithm


class Responses:
    tcp_connect_only = socket_icmp = {}

    tcp_connect_send_and_receive = {
        "response": 'HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.62 (Debian)\r\nContent-Length: 302\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n</p>\n<hr>\n<address>Apache/2.4.62 (Debian)</address>\n</body></html>\n',
        "ssl_flag": True,
    }

    ssl_version_scan = {
        "ssl_version": "TLSv1",
        "weak_version": True,
        "weak_cipher_suite": True,
        "ssl_flag": True,
    }

    ssl_certificate_scan = {
        "self_signed": True,
        "expired": True,
        "weak_signing_algo": True,
        "ssl_flag": True,
        "expiring_soon": False,
    }

    ssl_off = {"ssl_flag": False}

    none = None


class Substeps:
    tcp_connect_send_and_receive = {
        "method": "tcp_connect_send_and_receive",
        "response": {
            "condition_type": "or",
            "conditions": {
                "open_port": {"regex": "", "reverse": False},
                "ftp": {
                    "regex": "220-You are user number|530 USER and PASS required|Invalid command: try being more creative|220 \\S+ FTP (Service|service|Server|server)|220 FTP Server ready|Directory status|Service closing control connection|Requested file action|Connection closed; transfer aborted|Directory not empty",
                    "reverse": False,
                },
                "ftps": {
                    "regex": "220-You are user number|530 USER and PASS required|Invalid command: try being more creative|220 \\S+ FTP (Service|service|Server|server)|220 FTP Server ready|Directory status|Service closing control connection|Requested file action|Connection closed; transfer aborted|Directory not empty",
                    "reverse": False,
                },
                "http": {
                    "regex": "HTTPStatus.BAD_REQUEST|HTTP\\/[\\d.]+\\s+[\\d]+|Server: |Content-Length: \\d+|Content-Type: |Access-Control-Request-Headers: |Forwarded: |Proxy-Authorization: |User-Agent: |X-Forwarded-Host: |Content-MD5: |Access-Control-Request-Method: |Accept-Language: ",
                    "reverse": False,
                },
                "imap": {
                    "regex": "Internet Mail Server|IMAP4 service|BYE Hi This is the IMAP SSL Redirect|LITERAL\\+ SASL\\-IR LOGIN\\-REFERRALS ID ENABLE IDLE AUTH\\=PLAIN AUTH\\=LOGIN AUTH\\=DIGEST\\-MD5 AUTH\\=CRAM-MD5|CAPABILITY completed|OK IMAPrev1|LITERAL\\+ SASL\\-IR LOGIN\\-REFERRALS ID ENABLE IDLE NAMESPACE AUTH\\=PLAIN AUTH\\=LOGIN|BAD Error in IMAP command received by server|IMAP4rev1 SASL-IR|OK \\[CAPABILITY IMAP4rev1",
                    "reverse": False,
                },
                "mariadb": {
                    "regex": "is not allowed to connect to this MariaDB server",
                    "reverse": False,
                },
                "mysql": {
                    "regex": "is not allowed to connect to this MySQL server",
                    "reverse": False,
                },
                "nntp": {
                    "regex": "NetWare\\-News\\-Server|NetWare nntpd|nntp|Leafnode nntpd|InterNetNews NNRP server INN",
                    "reverse": False,
                },
                "pop3": {
                    "regex": "POP3|POP3 gateway ready|POP3 Server|Welcome to mpopd|OK Hello there",
                    "reverse": False,
                },
                "pop3s": {
                    "regex": "POP3|POP3 gateway ready|POP3 Server|Welcome to mpopd|OK Hello there",
                    "reverse": False,
                },
                "portmap": {
                    "regex": "Program\tVersion\tProtocol\tPort|portmapper|nfs\t2|nlockmgr\t1",
                    "reverse": False,
                },
                "postgressql": {
                    "regex": "FATAL 1\\:  invalid length of startup packet|received invalid response to SSL negotiation\\:|unsupported frontend protocol|fe\\_sendauth\\: no password supplied|no pg\\_hba\\.conf entry for host",
                    "reverse": False,
                },
                "pptp": {"regex": "Hostname: pptp server|Vendor: Fortinet pptp", "reverse": False},
                "smtp": {
                    "regex": "Fidelix Fx2020|ESMTP|Server ready|SMTP synchronization error|220-Greetings|ESMTP Arnet Email Security|SMTP 2.0",
                    "reverse": False,
                },
                "smtps": {
                    "regex": "Fidelix Fx2020|ESMTP|Server ready|SMTP synchronization error|220-Greetings|ESMTP Arnet Email Security|SMTP 2.0",
                    "reverse": False,
                },
                "rsync": {"regex": "@RSYNCD\\:", "reverse": False},
                "ssh": {
                    "regex": "openssh|\\-OpenSSH\\_|\\r\\nProtocol mism|\\_sshlib|\\x00\\x1aversion info line too long|SSH Windows NT Server|WinNT sshd|sshd| SSH Secure Shell|WinSSHD",
                    "reverse": False,
                },
                "telnet": {
                    "regex": "Check Point FireWall-1 authenticated Telnet server running on|Raptor Firewall Secure Gateway|No more connections are allowed to telnet server|Closing Telnet connection due to host problems|NetportExpress|WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING|Login authentication|recommended to use Stelnet|is not a secure protocol|Welcome to Microsoft Telnet Servic|no decompiling or reverse-engineering shall be allowed",
                    "reverse": False,
                },
            },
        },
    }

    tcp_connect_only = {
        "method": "tcp_connect_only",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": "", "reverse": False}},
        },
    }

    socket_icmp = {
        "method": "socket_icmp",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": "", "reverse": False}},
        },
    }

    ssl_version_scan = {
        "method": "ssl_version_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "weak_cipher_suite": {"reverse": False},
                "weak_version": {"reverse": False},
            },
        },
    }

    ssl_certificate_scan = {
        "method": "ssl_certificate_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "self_signed": {"reverse": False},
                "expired": {"reverse": False},
                "weak_signing_algo": {"reverse": False},
                "expiring_soon": {"reverse": False},
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

    @patch("core.lib.socket.is_weak_cipher_suite")
    @patch("core.lib.socket.create_tcp_socket")
    def test_ssl_version_scan_good(self, mock_connection, mock_cipher_check):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_cipher_check.return_value = False
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": False,
                "ssl_version": "TLSv1.3",
                "peer_name": "example.com",
                "weak_cipher_suite": False,
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST), False)
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": False,
                "service": "http",
                "peer_name": "example.com",
            },
        )

    @patch("core.lib.socket.is_weak_cipher_suite")
    @patch("core.lib.socket.create_tcp_socket")
    def test_ssl_version_scan_bad(self, mock_connection, mock_cipher_check):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.1"), True)
        mock_cipher_check.return_value = True
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": True,
                "ssl_version": "TLSv1.1",
                "weak_cipher_suite": True,
                "peer_name": "example.com",
            },
        )

    @patch("core.lib.socket.create_tcp_socket")
    @patch("core.lib.socket.crypto.load_certificate")
    @patch("core.lib.socket.ssl.get_server_certificate")
    def test_ssl_certificate_scan_good(self, mock_certificate, mock_x509, mock_connection):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=False,
            issuer="test_issuer",
            subject="test_subject",
            signing_algo="test_algo",
            expire_date=b"20250619153045Z",
        )
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": False,
                "ssl_flag": True,
                "service": "http",
                "self_signed": False,
                "expiring_soon": False,
                "weak_signing_algo": False,
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

    @patch("core.lib.socket.create_tcp_socket")
    @patch("core.lib.socket.crypto.load_certificate")
    @patch("core.lib.socket.ssl.get_server_certificate")
    def test_ssl_certificate_scan_bad(self, mock_certificate, mock_x509, mock_connection):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=True,
            issuer="test_issuer_subject",
            subject="test_issuer_subject",
            signing_algo="sha1",
            expire_date=b"20240619153045Z",
        )
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": True,
                "ssl_flag": True,
                "service": "http",
                "self_signed": True,
                "expiring_soon": True,
                "weak_signing_algo": True,
                "peer_name": "example.com",
            },
        )

    def test_response_conditions_matched(self):
        # tests the response conditions matched for different scan methods
        engine = SocketEngine()
        Substep = Substeps()
        Response = Responses()

        # socket_icmp
        self.assertEqual(
            engine.response_conditions_matched(Substep.socket_icmp, Response.socket_icmp),
            Response.socket_icmp,
        )

        # tcp_connect_send_and_receive, Port scan's substeps are taken for the test
        self.assertEqual(
            sorted(
                engine.response_conditions_matched(
                    Substep.tcp_connect_send_and_receive, Response.tcp_connect_send_and_receive
                )
            ),
            sorted(
                {"http": ["Content-Type: ", "Content-Length: 302", "HTTP/1.1 400", "Server: "]}
            ),
        )

        # tcp_connect_only
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.tcp_connect_only, Response.tcp_connect_only
            ),
            Response.tcp_connect_only,
        )

        # ssl_certificate_scan
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.ssl_certificate_scan, Response.ssl_certificate_scan
            ),
            {
                "expired": True,
                "self_signed": True,
                "weak_signing_algo": True,
            },
        )

        # ssl_version_scan
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.ssl_version_scan, Response.ssl_version_scan
            ),
            {
                "weak_version": True,
                "weak_cipher_suite": True,
            },
        )

        # ssl_* scans with ssl_flag = False
        self.assertEqual(
            engine.response_conditions_matched(Substep.ssl_version_scan, Response.ssl_off), []
        )

        # * scans with response None i.e. TCP connection failed(None)
        self.assertEqual(
            engine.response_conditions_matched(Substep.ssl_version_scan, Response.none), []
        )
