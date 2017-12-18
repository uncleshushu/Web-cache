#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import argparse
import logging
import socket
import threading

from handlers import *

LISTEN_PORT = 10086

MAX_CONNECTION = 1000


def threaded_proxy(listen_port, max_conn):
    '''
    http(s) proxy using multithread
    '''
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(("127.0.0.1", listen_port))
    listen_socket.listen(max_conn)

    # logger
    print("Proxy initiated.")

    while True:
        socket2c, addr = listen_socket.accept()

        # logger
        print()
        print('Get a new connection from:', addr)
        print('Starting a new proxy handler thread...')

        proxyHandlerThread = threading.Thread(target=proxy_handle, args=(socket2c,), kwargs={'require_auth': True, 'use_rules': True})
        proxyHandlerThread.start()


if __name__ == "__main__":
    threaded_proxy(LISTEN_PORT, MAX_CONNECTION)

