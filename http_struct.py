# coding: utf-8
"""
This module provides classes
that can construct a HTTP message structure
from a given file-like object,
as well as some useful functions.
"""

import base64
import re

_MAX_LINELEN = 65536
_MAX_HEADERCNT = 100


def is_keep_alive(httpBase):
    """
    find out whether the connection
    where the HTTP message comes from
    should be kept alive
    """
    # if no `connection` header, conn_type = None
    conn_type = httpBase.headers.get("Connection")
    proxy_conn_type = httpBase.headers.get("Proxy-Connection")

    # assume the value can only be 'keep-alive' or 'close'

    # give priority to `Proxy-Connection`
    if proxy_conn_type:
        if proxy_conn_type.lower() == "keep-alive":
            return True
        elif proxy_conn_type.lower() == "close":
            return False

    # `Proxy-Connection` doesn't exist
    # may be a direct request
    if conn_type:
        if conn_type.lower() == "keep-alive":
            return True
        elif conn_type.lower() == "close":
            return False

    # no `Proxy-Connection` nor `Connection`
    if httpBase.version_number >= (1, 1):
        return True
    else:
        return False


class HTTPMessage:
    """Base class for HTTP messages
    """

    def __init__(self, sockfile=None):
        self._sockfile = sockfile  # file object

        self.firstline = None  # str
        self.headers = {}  # dict
        self.body = None  # bytes

        self.http_version = None  # str
        self.version_number = None  # tuple
        # self.close_connection = True        # bool

        if sockfile:
            self.firstline = self._get_firstline()
            self.headers = self._get_headers()
            self.body = self._get_body()

    def _get_firstline(self):
        """get the first line of a HTTP message
        """
        raw_firstline = self._sockfile.readline(_MAX_LINELEN + 1)

        if not raw_firstline:
            # raw_firstline = b'' or None (?)
            # happens when readline hits EOF
            # means the connection is closed
            # TODO: raise user defined exceptions
            raise EOFError("connection closed")

        if len(raw_firstline) > _MAX_LINELEN:
            # TODO: raise user defined exceptions
            raise BufferError("First line too long")

        firstline = str(raw_firstline, errors="ignore").rstrip("\r\n")

        # print('fistline: %s'%(firstline))

        return firstline

    def _parse_firstline(self):
        """
        parse the first line
        should be implemented in subclasses
        """
        raise NotImplementedError

    def _get_headers(self):
        """parse headers to generate a dictionary
        """
        headers = {}
        while True:
            raw_headerline = self._sockfile.readline(_MAX_LINELEN + 1)
            if len(raw_headerline) > _MAX_LINELEN:
                raise ValueError("Header line too long")

            headerline = str(raw_headerline, errors="ignore").rstrip("\r\n")
            if headerline in ("\r\n", "\n", ""):
                break

            field, value = re.split(r"[:]\s*", headerline, 1)
            headers[field] = value

            if len(self.headers) > _MAX_HEADERCNT:
                raise ValueError("got more than %d headers" % _MAX_HEADERCNT)

        return headers

    def _get_body(self):
        """get the body
        """
        body = b""

        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                raw_chunklen = self._sockfile.readline()
                body += raw_chunklen
                chunklen = int(raw_chunklen.decode().rstrip("\r\n"), base=16)
                body += self._sockfile.read(chunklen)
                # read a line of '\r\n' (necessary?)
                body += self._sockfile.readline()

                if chunklen == 0:
                    break

        else:
            # 0 if no `content-length` header
            nbytes = int(self.headers.get("Content-Length", "0"))
            if nbytes > 0:
                body = self._sockfile.read(nbytes)
            else:
                # HTTP/1.0
                # if self.version_number < (1, 1):
                #     self.body = self.sockfile.read()
                body = None

        return body

    def to_byte(self, recount_len=False):
        """serialize the object
        """
        data = (self.firstline + "\r\n").encode()

        if recount_len:
            self.headers["Content-Length"] = 0 if self.body is None else len(
                self.body)

        if self.headers:
            headerlines = [
                "{}: {}\r\n".format(field, value).encode()
                for (field, value) in self.headers.items()
            ]
            data += b"".join(headerlines)

        data += b"\r\n"

        if self.body:
            data += self.body

        return data


class HTTPRequest(HTTPMessage):
    def __init__(self, sockfile=None):
        super(HTTPRequest, self).__init__(sockfile)

        self.method = None  # str
        self.path = None  # str
        self.username = None  # str
        self.password = None  # str

        if sockfile:
            self.method, self.path, self.http_version, \
                self.version_number = self._parse_requestline()

    def _parse_requestline(self):
        """
        parse request line to get
        method, path and http_version and version_number
        """
        words = self.firstline.split()
        if len(words) == 3:
            method, path, http_version = words

            # RFC 2145 section 3.1 says there can be only one "." and
            #   - major and minor numbers MUST be treated as
            #      separate integers;
            #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
            #      turn is lower than HTTP/12.3;
            #   - Leading zeros MUST be ignored by recipients.
            version_number = http_version.split("/", 1)[1].split(".")

            if len(version_number) != 2:
                raise ValueError("HTTP version format error")

            version_number = int(version_number[0]), int(version_number[1])

            if version_number >= (2, 0):
                raise ValueError("Invalid HTTP Version (%s)" % http_version)

            return method, path, http_version, version_number

        else:
            # not in the form like 'GET /hello.png HTTP/1.1'
            raise ValueError("Request line format error")


class HTTPResponse(HTTPMessage):
    def __init__(self, sockfile=None):
        super(HTTPResponse, self).__init__(sockfile)

        self.status_code = None  # int
        self.reason = None  # str

        if sockfile:
            self.http_version, self.version_number, \
                self.status_code, self.reason = self._parse_responseline()

    def _parse_responseline(self):
        """
        parse the response line to get
        http_version, version_number, status_code and reason
        """
        words = self.firstline.split()

        http_version = words[0]

        version_number = http_version.split("/", 1)[1].split(".")
        version_number = int(version_number[0]), int(version_number[1])

        status_code = int(words[1])
        reason = "".join(words[2:])

        return http_version, version_number, status_code, reason


class ProxyRequest(HTTPRequest):
    def __init__(self, sockfile):
        super().__init__(sockfile)
        self.relative_path = self.path.replace(
            "http://" + self.headers["Host"], "")

        self.proxy_user = None
        self.proxy_pass = None

        self.proxy_user, self.proxy_pass = self._get_proxy_user_pass()

    def _get_proxy_user_pass(self):
        proxy_auth = self.headers.get("Proxy-Authorization")
        if proxy_auth:
            # print('auth str: ', proxy_auth)
            auth_method, auth_str = proxy_auth.split()
            if auth_method.lower() == "basic":
                user_pass = base64.b64decode(auth_str).split(b":")
                proxy_user = user_pass[0].decode()
                proxy_pass = user_pass[1].decode()

                # print('proxy_user: ', proxy_user)
                # print('proxy_pass: ', proxy_pass)

            return proxy_user, proxy_pass
        else:
            return None, None
