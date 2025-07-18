from src.stream import Stream, TCPStream, HTTPStream
from src.db_manager import DBManager
import string

################################################################################
# HTTP


def curl(self, stream: HTTPStream):
    """block curl user-agent"""
    message = stream.current_http_message
    return "curl" in message.headers.get("user-agent")


def username(self, stream: HTTPStream):
    """
    block usernames longer than 10 characters for register endpoint
    """
    message = stream.current_http_message
    if "register" in message.url and "POST" in message.method:
        username = message.parameters.get("username")
        if len(username) > 10:
            return True
    else:
        return False


def block_leak(self, stream: HTTPStream):
    """
    if responding to /home request and a flag is in the response, block
    only valid for _out modules
    """
    message = stream.current_http_message
    previous_message = stream.previous_http_messages
    return "/home" in previous_message.path and "flag{" in message.raw_body


def replace_word_http(self, stream: HTTPStream):
    """replace leet with l33t"""
    # the actual data sent by the socket is stream.current_message, so you can't just modify stream.current_http_message
    stream.current_message = stream.current_message.replace(b"leet", b"l33t")
    return False  # do not block message, just change its contents


################################################################################
# TCP

# global state, useful to save state between connections
passwords = []


def nonPrintableChars(self, stream: TCPStream):
    """block packets with non printable chars"""
    return any([chr(c) not in string.printable for c in stream.current_message])


def password(self, stream: TCPStream):
    """block passwords longer than 10 characters or already seen passwords"""
    if b"Insert password:" in stream.previous_messages[0]:
        current_password = stream.current_message.strip()
        if current_password in passwords:
            return True
        if len(current_password) > 10:
            return True
        passwords.append(current_password)
    return False


def replace_word_tcp(self, stream: TCPStream):
    """replace leet with l33t"""
    stream.current_message = stream.current_message.replace(b"leet", b"l33t")
    return False  # do not block packet, just change its contents
