# coding: utf-8
"""
This module includes handler
for common HTTP methods,
as well as some classes for implementing
an HTTP client, an HTTP server,
an HTTP proxy or a Web cache.
"""

import hashlib
import os
import re
import select
import socket
import sys
import urllib.parse
from datetime import datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
from threading import Thread

from db_manager import DBManager
from http_struct import HTTPResponse, ProxyRequest

###########################################
# exceptions
###########################################


class HandlerError(Exception):
    """
    Base class for exceptions in this module.
    """

    pass


class AuthFailure(HandlerError):
    """
    Request authorization failure.
    """

    def __init__(self, message):
        self.message = message


###########################################
# functions for common clients and servers
###########################################


def authenticate(cursor, username, password):
    """
    Authenticate a user.
    """

    pass


def client_GET(httpRequest, socket2s):
    # print('Now do client GET')
    socket2s.sendall(httpRequest.to_byte())
    # print('GET request sent:')
    # print(httpRequest.to_byte())


def client_POST(httpRequest, socket2s):
    # print('Now do client POST')
    socket2s.sendall(httpRequest.to_byte())
    # print('POST request sent')


def client_REQUEST(httpRequest, socket2s):
    # print('Now do client REQUEST')

    socket2s.sendall(httpRequest.to_byte())

    # print('request sent:')
    # print(httpRequest.to_byte().decode(errors='ignore'))


def server_RESPONSE(httpResponse, socket2c, recount_len=False):
    # print('Now do RESPONSE')

    socket2c.sendall(httpResponse.to_byte(recount_len))

    # print('response sent:')
    # print(httpResponse.to_byte())


###########################################
# functions for proxy
###########################################
# def proxy_authorize(dbManager):
#     def decorator(func):
#         @functools.wraps(func)
#         def wrapper(proxyRequest, socket2s):
#             if not proxyRequest.proxy_user:
#                 raise AuthFailure('User can not be empty.')

#             try:
#                 is_valid = dbManager.auth_user(proxyRequest.proxy_user,
#                                                proxyRequest.proxy_pass)
#                 if not is_valid:
#                     raise AuthFailure('Password incorrect.')
#             except ValueError as valueError:
#                 # user doesn't exist
#                 raise AuthFailure(str(valueError))

#         return wrapper

#     return decorator


AUTH_FAILURE_RES = HTTPResponse()
AUTH_FAILURE_RES.firstline = "HTTP/1.1 407 Proxy Authentication Required"
AUTH_FAILURE_RES.headers = {
    "Connection": "close",
    "Proxy-Authenticate": 'Basic realm="Authentication Required"',
}
AUTH_FAILURE_RES.body = None


def proxy_authorize(dbManager, proxyRequest, socket2c):
    if not proxyRequest.proxy_user:
        AUTH_FAILURE_RES.body = b"Proxy Authentication Required."
        print("sent 'Proxy Authentication Required' message")
        return False

    try:
        # print('username provided: ', proxyRequest.proxy_user)
        # print('password provided: ', proxyRequest.proxy_pass)
        is_valid = dbManager.user_auth(proxyRequest.proxy_user,
                                       proxyRequest.proxy_pass)
        if not is_valid:
            AUTH_FAILURE_RES.body = b"Incorrect Token."
            AUTH_FAILURE_RES.headers[
                "Proxy-Authenticate"] = 'Basic realm="Incorrect Token"'

            print("sent 'Unauthorized' message")

            return False
        else:
            return True

    except ValueError as valueError:
        print(valueError, file=sys.stderr)


def forward_connect(proxyRequest, socket2s):
    """
    Connect the host specified in `httpRequest`
    """
    default_port = 443 if proxyRequest.method == "CONNECT" else 80

    host_port = proxyRequest.headers["Host"].rsplit(":")
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) == 2 else default_port
    socket2s.connect((host, port))


FORBIDDEN_RES = HTTPResponse()
FORBIDDEN_RES.firstline = "HTTP/1.1 403 Forbidden"
FORBIDDEN_RES.headers = {"Connection": "close"}
FORBIDDEN_RES.body = b"403 Forbidden\n \
                       You are not allowed to visit this site.\n"


def filter(proxyRequest, rules):
    is_forbidden = False
    if not rules:
        is_forbidden = False
        return is_forbidden

    host_port = proxyRequest.headers["Host"].rsplit(":")
    host = host_port[0]
    # e.g.: "www.baidu.com":""
    redirect_host = rules.get(host)
    if redirect_host is None:
        # e.g.: "www.baidu.com:443":""
        redirect_host = rules.get(proxyRequest.headers["Host"])

    if redirect_host is None:
        # no rule for this host
        is_forbidden = False

    elif redirect_host == "":
        # forbidden
        is_forbidden = True
        print("403 Forbidden")

    else:
        is_forbidden = False
        proxyRequest.firstline = proxyRequest.firstline.replace(
            proxyRequest.headers.get("Host"), redirect_host)
        proxyRequest.path = proxyRequest.path.replace(
            proxyRequest.headers.get("Host"), redirect_host)
        proxyRequest.headers["Host"] = redirect_host

        print("redirect_host: ", redirect_host)

    return is_forbidden


def proxy_REQUEST(proxyRequest, socket2s):
    if proxyRequest.headers.get("Proxy-Authorization"):
        proxyRequest.headers.pop("Proxy-Authorization")
    if proxyRequest.headers.get("Proxy-Connection"):
        proxyRequest.headers.pop("Proxy-Connection")
    if proxyRequest.path.startswith("http"):
        # some servers can not parse path beginning with 'http://'
        proxyRequest.firstline = "".join([
            proxyRequest.method,
            " ",
            proxyRequest.relative_path,
            " ",
            proxyRequest.http_version,
        ])

    client_REQUEST(proxyRequest, socket2s)


def proxy_CONNECT(socket2c):
    """
    Establish a HTTPS tunnel
    specified by the given HTTPRequest instance.
    """
    socket2c.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # logger
    # print("HTTPS tunnel established.")


def forward_TCP(socket_in, socket_out, max_size):
    """
    When `socket_in` is readable,
    call this method to
    forward some bytes to `socket_out`.
    """

    data = socket_in.recv(max_size)

    if not data:
        # connection closed
        raise EOFError("socket {} closed".format(socket_in.getpeername()))

    socket_out.sendall(data)


def tunneling(socket_a, socket_b):
    conns = [socket_a, socket_b]
    while True:
        rlist, wlist, xlist = select.select(conns, [], [], 10)

        if xlist or not rlist:
            break

        for rsock in rlist:
            other = conns[1] if rsock is conns[0] else conns[0]
            try:
                forward_TCP(rsock, other, 65536)
            except EOFError as eofError:
                raise eofError


def proxy_handle(socket2c,
                 require_auth=False,
                 use_rules=False,
                 with_cache=False):
    socket2c_file = socket2c.makefile("rb", -1)
    try:
        proxyRequest = ProxyRequest(socket2c_file)
    except EOFError:
        socket2c.close()
        return

    # print('original request:')
    print("[+] {}: {}".format(socket2c.getpeername(), proxyRequest.firstline))

    #########################################
    # Codes for authorization and filter
    if require_auth or use_rules or with_cache:
        dbManager = DBManager()

    if require_auth:
        isvalid = proxy_authorize(dbManager, proxyRequest, socket2c)
        if not isvalid:
            server_RESPONSE(AUTH_FAILURE_RES, socket2c, recount_len=True)
            socket2c.close()
            return

    if use_rules:
        rules = dbManager.get_rules(proxyRequest.proxy_user)
        is_forbidden = filter(proxyRequest, rules)
        if is_forbidden:
            server_RESPONSE(FORBIDDEN_RES, socket2c, recount_len=True)
            socket2c.close()
            return

    # End codes for authorization and filter
    ###########################################

    # clients may reuse the connection to request another 'Host'
    # so record the first requested 'Host'
    first_host = proxyRequest.headers["Host"]

    socket2s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        forward_connect(proxyRequest, socket2s)
    except BlockingIOError:
        pass
    socket2s_file = socket2s.makefile("rb", -1)

    if proxyRequest.method == "CONNECT":
        # logger
        # print('serving as an HTTPS proxy...')
        try:
            proxy_CONNECT(socket2c)
            tunneling(socket2c, socket2s)
        except EOFError as eofError:
            # logger
            # print(eofError)
            pass
        except BlockingIOError:
            pass

    else:
        # logger
        # print('serving as an HTTP proxy...')

        while True:
            try:
                if with_cache:
                    validation_result = validate_cache(proxyRequest, dbManager)

                    if validation_result["need_revalidate"]:
                        # cache expired or client requires revalidation
                        proxy_REQUEST(proxyRequest, socket2s)
                        httpResponse = HTTPResponse(socket2s_file)
                        if httpResponse.status_code == 304:
                            # response to conditional GET, unmodified
                            print("Unmodified, cache hit.")
                            cache_path = validation_result["cache_path"]
                            if cache_path:
                                with open(cache_path, "rb") as cache_file:
                                    httpResponse = HTTPResponse(cache_file)
                        else:
                            # modified response or normal response
                            if validation_result["cache_response"]:
                                # client allows the proxy to cache response
                                is_cached = do_cache(
                                    proxyRequest.headers["Host"],
                                    proxyRequest.relative_path,
                                    httpResponse,
                                    dbManager,
                                )
                                if is_cached:
                                    print("Response cached.")
                                else:
                                    print("Server does not allow cache.")

                            else:
                                print("Client does not allow cache.")

                    else:
                        # unexpired cache hit
                        print("Unexpired, cache hit.")
                        with open(validation_result["cache_path"],
                                  "rb") as cache_file:
                            httpResponse = HTTPResponse(cache_file)

                        httpResponse.headers["Date"] = format_datetime(
                            datetime.now())

                else:
                    # without cache, forward the request
                    proxy_REQUEST(proxyRequest, socket2s)
                    httpResponse = HTTPResponse(socket2s_file)

                server_RESPONSE(httpResponse, socket2c)

                proxyRequest = ProxyRequest(socket2c_file)
                # print('original request:')
                print("[+]", proxyRequest.firstline)
                if use_rules:
                    is_forbidden = filter(proxyRequest, rules)
                    if is_forbidden:
                        server_RESPONSE(
                            FORBIDDEN_RES, socket2c, recount_len=True)
                        socket2c.close()
                        socket2s.close()
                        return
                if not (proxyRequest.headers["Host"] == first_host):
                    # force the client to create a new connection
                    # for another 'Host'
                    socket2c.close()
                    socket2s.close()
                    # print("Host changed!")
                    return
            except EOFError as eofError:
                # logger
                # print(eofError)
                break
            except BlockingIOError:
                pass

    socket2c.close()
    socket2s.close()


###########################################
# functions for web-cache
###########################################
def validate_cache(proxyRequest, dbManager):
    result = {
        "need_revalidate": False,
        "cache_response": True,
        "cache_path": None
    }

    #########################################################
    # check cache control header in request
    cache_control = proxyRequest.headers.get("Cache-Control")
    # If `Cache-Control` exists,
    # it will overwhelm other
    # cache related headers.
    max_age = None
    if cache_control:
        cache_directives = re.split(r",\s*", cache_control)
        # Possible values:
        # no-cache
        # no-store
        # max-age=delta-seconds
        max_age = None
        if "no-cache" in cache_directives:
            # must revalidate cache
            result["need_revalidate"] = True
        else:
            result["need_revalidate"] = False

        if "no-store" in cache_directives:
            # do not cache the response
            result["cache_response"] = False

        for _ in cache_directives:
            if _.startswith("max-age"):
                # proxy should only respond with
                # cache stored for less than
                # `max_age` seconds
                max_age = _.split("=")[1]
                break
    # end check cache control in request
    ######################################################

    ######################################################
    # validate cache and replace cache-related headers if exist
    url = "http://" + proxyRequest.headers["Host"] + proxyRequest.relative_path
    # print('query cache_info with url:', url, file=sys.stderr)

    cache_info = dbManager.query_cache_info(url)
    if not cache_info:
        print("No cache for this url.", file=sys.stderr)
        result["need_revalidate"] = True
        # return now
        return result

    result["cache_path"] = cache_info["cache_path"]

    # if not result['cache_path']:
    #     print('cache_path is None!', file=sys.stderr)

    # else:
    #     print('cache_path:', result['cache_path'],file=sys.stderr)

    if cache_info["Last-Modified"]:
        proxyRequest.headers["If-Modified-Since"] = cache_info["Last-Modified"]

    if cache_info["max-age"]:
        if max_age:
            # client only accepts cache stored less than `max-age` seconds
            if timedelta(seconds=max_age
                         ) + cache_info["cached_time"] < datetime.now():
                result["need_revalidate"] = True
            else:
                result["need_revalidate"] = False

            return result

        if (timedelta(seconds=cache_info["max-age"]) +
                cache_info["cached_time"] < datetime.now()):
            # expired
            if cache_info["ETag"]:
                # modify the request header for revalidation
                proxyRequest.headers["If-None-Match"] = cache_info["ETag"]

            result["need_revalidate"] = True

        else:
            # not expired
            result["need_revalidate"] = False or result["need_revalidate"]

    return result


# def revalidate_cache(proxyRequest, socket2s, socket2s_file):
#     proxy_REQUEST(proxyRequest, socket2s)
#     httpResponse = HTTPResponse(socket2s_file)
#     if httpResponse.status_code == 304
#     pass


def do_cache(host_port, path, httpResponse, dbManager):
    cache_info = {
        "cached_time": datetime.now(),
        "Last-Modified": httpResponse.headers.get("Last-Modified"),
        "max-age": None,
        "ETag": httpResponse.headers.get("ETag"),
        "cache_path": None,
    }

    cache_control = httpResponse.headers.get("Cache-Control")
    if cache_control:
        cache_directives = re.split(r",\s*", cache_control)
        if "no-store" in cache_directives or "private" in cache_directives:
            # response is not cached
            return False

        if "no-cache" in cache_directives \
                or "must-revalidate" in cache_directives:
            cache_info["max-age"] = 0
        for _ in cache_directives:
            if _.startswith("max-age"):
                cache_info["max-age"] = _.split("=")[1]
                break

    else:
        # `Cache-Control` doesn't exist
        expires = httpResponse.headers.get("Expires")
        if expires:
            print("expires:", expires, file=sys.stderr)
            time_delta = (parsedate_to_datetime(expires).replace(tzinfo=None) -
                          datetime.now())
            cache_info["max-age"] = int(time_delta.total_seconds())

    dir_path = os.path.join("caches", urllib.parse.quote(host_port))
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    path_hash_str = hashlib.md5(path.encode()).hexdigest()
    cache_path = os.path.join(dir_path, path_hash_str)

    with open(cache_path, "wb") as cache_file:
        cache_file.write(httpResponse.to_byte())

    cache_info["cache_path"] = cache_path

    url = "http://" + host_port + path
    # print('store cache_info with url:', url, file=sys.stderr)
    dbManager.store_cache_info(url, cache_info)
    # response cached
    return True


###########################################
# handler functions
###########################################

###########################################
# handler classes
###########################################


class ProxyHandlerThread(Thread):
    """
    A thread that handles proxy requests
    in blocking mode.
    """

    def __init__(self, socket2c):
        self.socket2c = socket2c

        self._socket2s_file = None
        # self._socket2s_file = self.socket2s.makefile('rb', -1)
