#!/usr/bin/python3
# -*- coding: utf-8 -*-
from pexpect import pxssh


def send_command(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print(s.before)


def connect(host, user, password):
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        return s
    except:
        print('[-] error connecting')
        exit(0)


s = connect('127.0.0.1', 'me', '588014')
send_command(s, 'uname -v')
