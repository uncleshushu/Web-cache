# Web-cache

A web-cache implemented in Python

## Features

### HTTP cache

This program will cache HTTP response and validate caches according to cache-related headers.

### User authorization

You can add users to the database and require clients to provide authorization information.

### URL filter

You can set URL redirection and forbidden rules for each user.

## Prerequisites

- python3 (>= 3.5)

- sqlite3: Command line interface for SQLite 3

## Installation

The web-cache is implemented in Python, so you just need to extract the ZIP file.

## Usage

### Basic usage

#### Start the web-cache

In shell (or cmd.exe), `cd` into the `web-cache` folder and run

```bash
python3 web-cache.py
```

Then the web-cache process will listen on `127.0.0.1:10086` by default.

#### Delete caches

In shell, run:

```bash
sh clear_cache.sh
```

### Detailed usage

```text
usage: run_threaded.py [-h] [--host HOST] [--port PORT] [--maxconn MAXCONN]
                       [--auth] [--filter] [--nocache]

web-cache.py v0.2

optional arguments:
  -h, --help         show this help message and exit
  --host HOST        Default: 127.0.0.1
  --port PORT        Default: 10086
  --maxconn MAXCONN  Connection limit. Default: 1000
  --auth             Require proxy authorization. Default: False
  --filter           Use URL filter. Default: False
  --nocache          No cache. Default: False
```

#### Add users

In shell, run

```bash
python3 add_user.py
```

and add users interactively.

An example user `admin` with password `password` is already inserted into the database.

#### Add filter rules

If you want to add filter rules for a user named `someone`, go to the [rules](rules) folder, and create a json file named `someone.rule` following the example of [admin.rule](rules/admin.rule).

## How it works

### Concurrency

Current implementation is multi-threaded. It uses Python's `threading` module to handle concurrency.

### HTTP message parsing

In `http_struct.py`, the class `HTTPMessage` and its two sub-classes, `HTTPRequest` and `HTTPResponse`, are the structured representation of HTTP messages. These classes are constructed from a file-like object, which can be initialized by a call to `socket.makefile()` on a stream socket.

### Forwarding and caching

In `handlers.py`, `handle()` does the loop of cache-validation, forwarding and caching. Upon receiving each request, it will first validate if the cache for the request exists and if the cache is fresh according to cache-related headers in the request. If hit, it will respond to the client with the cache, else it will do conditional GET(if cache expires) or a plain GET to remote server, then responds to client with the revalidated local cache or the modified resource from remote server (and caches the modified resource).

## References

- [RFC2616 section 14: Header Field Definitions](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html)