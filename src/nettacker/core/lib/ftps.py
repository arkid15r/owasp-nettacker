import ftplib

from nettacker.core.lib.ftp import FTPEngine, FTPLibrary


class FtpsLibrary(FTPLibrary):
    client = ftplib.FTP_TLS


class FtpsEngine(FTPEngine):
    library = FtpsLibrary
