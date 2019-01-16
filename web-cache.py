#!/usr/bin/env python3
# -*- coding:utf-8 -*-

__version__ = "0.2"
__description__ = "Web cache in Python"
__author__ = "Shu Jiang"

import argparse
import socket
import sqlite3
import threading

from handlers import proxy_handle

HOST = "127.0.0.1"
LISTEN_PORT = 10086

MAX_CONNECTION = 1000

DB = "proxy_db.db"


def threaded_proxy(host, port, max_conn, require_auth, use_filter, with_cache):
    """
    http(s) proxy using multithread
    """
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((host, port))
    listen_socket.listen(max_conn)

    # logger
    print("Listening on %s:%d ..." % (host, port))

    while True:
        socket2c, addr = listen_socket.accept()

        # logger
        print()
        print("[+] Get a new connection from: {} ,starting a new thread...".
              format(addr))

        proxyHandlerThread = threading.Thread(
            target=proxy_handle,
            args=(socket2c, ),
            kwargs={
                "require_auth": require_auth,
                "use_rules": use_filter,
                "with_cache": with_cache,
            },
        )
        proxyHandlerThread.start()


def main():
    parser = argparse.ArgumentParser(
        description="webcache.py v%s" % __version__)

    parser.add_argument(
        "--host", default=HOST, help="Listening hostname. Default: %s" % HOST)
    parser.add_argument(
        "--port",
        default=LISTEN_PORT,
        help="Listening port. Default: %d" % LISTEN_PORT)
    parser.add_argument(
        "--maxconn",
        default=MAX_CONNECTION,
        help="Connection limit. Default: %d" % MAX_CONNECTION,
    )
    parser.add_argument(
        "--auth",
        action="store_true",
        default=False,
        help="Require proxy authorization. Default: False",
    )
    parser.add_argument(
        "--filter",
        action="store_true",
        default=False,
        help="Use URL filter. Default: False",
    )
    parser.add_argument(
        "--nocache",
        action="store_true",
        default=False,
        help="No cache. Default: False")
    args = parser.parse_args()

    host = args.host
    port = int(args.port)
    max_conn = int(args.maxconn)
    require_auth = args.auth
    use_filter = args.filter
    with_cache = not args.nocache

    try:
        with open("init.sql", "r") as dbinit_file:
            dbinit_script = dbinit_file.read()

        db_conn = sqlite3.connect(DB)
        db_conn.cursor().executescript(dbinit_script)
        db_conn.commit()
        db_conn.close()

        threaded_proxy(host, port, max_conn, require_auth, use_filter,
                       with_cache)
    except KeyboardInterrupt:
        pass
    except BlockingIOError:
        pass


if __name__ == "__main__":
    main()
