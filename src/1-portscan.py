#!/usr/bin/python3
# -*- coding: utf-8 -*-
from socket import *
from threading import *

screenLock = Semaphore(value=1)


def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('some information\r\n')
        results = connSkt.recv(1024)
        screenLock.acquire()
        print('[+] {}/tcp open'.format(tgtPort))
        print('[+] ' + str(results))
    except:
        screenLock.acquire()
        print('[-] {}/tcp closed'.format(tgtPort))
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '{}': Unknown host".format(tgtHost))
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print("\n[+] Scan Results for: " + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)

    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, tgtPort))
        t.start()

def main():
    import optparse
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')

    (options, args) = parser.parse_args()

    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(', ')

    if tgtPorts[0] == None or tgtHost == None:
        print(parser.usage)
        exit(0)

    portScan(tgtHost, tgtPorts)


if __name__ == '__main__':
    main()
