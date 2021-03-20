import ctypes, ctypes.wintypes
import hashlib
import shutil
import os, os.path
from pathlib import Path
import random
import socket
import ssl
import time
import threading
# import subprocess
import argparse
from functools import partial
import msvcrt

HANDLE = ctypes.wintypes.HANDLE
byref = ctypes.byref
LPCWSTR = ctypes.wintypes.LPCWSTR
ULONG = ctypes.wintypes.ULONG
DWORD = ctypes.wintypes.DWORD
bcrypt = ctypes.WinDLL('bcrypt', use_last_error=True)
iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)

random.seed()
SCRIPT_PATH = os.path.dirname(__file__)

class AES():
  
  class BCRYPT_KEY_DATA_BLOB_HEADER(ctypes.Structure):
    _fields_ = [('dwMagic', ULONG), ('dwVersion', ULONG), ('cbKeyData', ULONG)]

  def __init__(self, key):
    self.BCryptProviderH = HANDLE(0)
    bcrypt.BCryptOpenAlgorithmProvider(byref(self.BCryptProviderH), LPCWSTR('AES'), LPCWSTR(None), ULONG(0))
    BCryptKeyL = DWORD(0)
    BCryptKeyLC = ULONG(0)
    bcrypt.BCryptGetProperty(self.BCryptProviderH, LPCWSTR('ObjectLength'), byref(BCryptKeyL), ULONG(ctypes.sizeof(BCryptKeyL)), byref(BCryptKeyLC), ULONG(0))
    self.BCryptKeyH = HANDLE(0)
    self.BCryptKey = ctypes.create_string_buffer(BCryptKeyL.value)
    BCryptKeyI = ctypes.create_string_buffer(key)
    bcrypt.BCryptGenerateSymmetricKey(self.BCryptProviderH, byref(self.BCryptKeyH), byref(self.BCryptKey), ULONG(BCryptKeyL.value), BCryptKeyI, ULONG(len(key)), ULONG(0))

  def _AESOperation(self, op, iv, input_text):
    BOpIV = ctypes.create_string_buffer(iv)
    BOpInput = ctypes.create_string_buffer(input_text)
    BOpOutput = ctypes.create_string_buffer(len(BOpInput) - 1)
    BOpOuputS = ULONG(0)
    getattr(bcrypt, 'BCrypt' + op)(self.BCryptKeyH, BOpInput, ULONG(len(BOpInput) - 1), None, BOpIV, ULONG(len(BOpIV) - 1), BOpOutput, ULONG(len(BOpOutput)), byref(BOpOuputS), ULONG(0))
    return bytes(BOpOutput[0:BOpOuputS.value])

  def Cipher(self, iv, plain_text):
    return self._AESOperation('Encrypt', iv, plain_text)

  def Decipher(self, iv, cipher_text):
    return self._AESOperation('Decrypt', iv, cipher_text)

  def __del__(self):
    bcrypt.BCryptDestroyKey(self.BCryptKeyH, ULONG(0))
    bcrypt.BCryptCloseAlgorithmProvider(self.BCryptProviderH, ULONG(0))

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.__del__()


class MiXplorerTCP():

  def __init__(self, port, password, secure=False, kpassword=None):
    self.ip = socket.gethostbyname(socket.gethostname())
    self.port = port
    self.md5_password = hashlib.md5(password.encode('utf-8')).hexdigest().encode('utf-8')
    self.secure = secure
    self.lsock = None
    if secure:
      self.context = ssl.SSLContext(ssl.PROTOCOL_TLS)
      self.context.maximum_version = ssl.TLSVersion.TLSv1_2
      if kpassword:
        try:
          self.context.load_cert_chain(r'%s\%s' % (SCRIPT_PATH, 'cert.pem'), r'%s\%s' % (SCRIPT_PATH, 'key.pem'), password=kpassword)
        except:
          print('Could not load cert.pem and key.pem with password ' + kpassword)

  def Sendto(self, ip, src, dst):
    src_list = []
    dst_list = []
    for s in src:
      if os.path.isdir(s):
        s_list = list((e[0] + '\\' + f) for e in os.walk(s) for f in e[2])
        src_list += s_list
        dst_list += list((dst.rstrip('/') + (dst and '/') + os.path.relpath(f, os.path.dirname(s)).replace('\\', '/')) for f in s_list)
      else:
        src_list += [s]
        if len(src) <= 1:
          dst_list += [dst or os.path.basename(s)]
        else:
          dst_list += [dst.rstrip('/') + (dst and '/') + os.path.basename(s)]
    print('Initiating the transfer to %s:%s...' % (ip, self.port))
    so = socket.socket()
    if self.secure:
      sock = self.context.wrap_socket(so, server_side=False)
    else:
      sock = so
    try:
      sock.connect((ip, self.port))
    except:
      print('Could not connect to %s:%s' % (ip, self.port))
      sock.close()
      return False
    with AES(self.md5_password) as aes:
      for s, d in zip(src_list, dst_list):
        try:
          message = (b'true' if self.secure else b'false') + b'\n' + self.md5_password + b'\n' + str(os.path.getsize(s)).encode('utf-8') + b'\n' + str(int(os.path.getmtime(s))).encode('utf-8') + b'000\n' + d.encode('utf-8')
        except:
          print('Could not open the file %s' % s)
          continue
        plain_message = message + b'\x00' * (15 - (len(message) + 15) % 16)
        iv = bytes(random.randint(0,255) for i in range(16))
        cipher_message = aes.Cipher(iv, plain_message)
        try:
          sock.sendall(iv + cipher_message)
          if sock.recv(100) != b'Write the binary now...':
            raise
          print('Sending %s...' % s) 
        except:
          print('Could not initiate the transfer to %s:%s' % (ip, self.port))
          sock.close()
          return False
        try:
          file = open(s, 'rb')
        except:
          print('Could not open the file %s' % s)
          sock.close()
          continue
        try:
          shutil.copyfileobj(file, sock.makefile('wb'))
        except:
          print('Could not achieve the transfer to %s:%s' % (ip, self.port))
          sock.close()
          return False
        finally:
          file.close()
        try:
          if sock.recv(100) == b'finished':
            print('File %s sent as %s' % (s, d))
          else:
            print('Could not achieve the transfer to %s:%s' % (ip, self.port))
        except:
          print('Could not achieve the transfer to %s:%s' % (ip, self.port))
      sock.close()

  def SendtoFirst(self, src, dst):
    ip_p, ip_h = self.ip.rsplit('.', 1)
    ip_arp = []
    print('Looking for a device running a server on port %s...' % self.port, end ='', flush=True)
#    process_result = subprocess.run('for /F %%1 in (\'arp -a ^| find "  %s." ^| sort\') do @echo %%1' % ip_p.rsplit('.', 2)[0], shell=True, capture_output=True)
#    if process_result.returncode == 0:
#      ip_arp = (ip.strip() for ip in process_result.stdout.decode('utf-8').splitlines()[:-1])
    s = ULONG(0)
    iphlpapi.GetIpNetTable(None, byref(s), True)
    s = ULONG(s.value + 24 * 10)
    b = ctypes.create_string_buffer(s.value)
    iphlpapi.GetIpNetTable(b, byref(s), True)
    g = (('.'.join(str(int(e)) for e in b[20+24*i:24+24*i]), int.from_bytes(b[24+24*i], "little")) for i in range(int.from_bytes(b[0:4], "little")))
    ip_arp = list(e[0] for e in g if e[1] != 2 and '.'.join(e[0].split('.')[0:2]) == '.'.join(self.ip.split('.')[0:2]))[:-1]
    ip_gen = (ip for g in (ip_arp, ('.'.join((ip_p, str(h))) for h in range(1, 254) if not '.'.join((ip_p, str(h))) in ip_arp)) for ip in g if ip != self.ip)
    for ip in ip_gen:
      print(' ' + ip.ljust(15), end ='\b'*16, flush=True)
      so = socket.socket()
      if self.secure:
        sock = self.context.wrap_socket(so, server_side=False)
      else:
        sock = so
      sock.settimeout(0.5)
      try:
        sock.connect((ip, self.port))
        sock.send(b'*model*')
        print('\r\nFound %s' % sock.recv(1024).decode('utf-8'))
        sock.close()
        time.sleep(0.5)
        if self.Sendto(ip, src, dst) == False:
          print('Looking for a device running a server on port %s...' % self.port, end ='', flush=True)
          raise
        return
      except:
        sock.close()
    print('\r\nNo device was found')

  def _StartReceiving(self, user, device, root):
    ren = lambda f, c: (' (%s)' % c if c else '').join(os.path.splitext(f))
    so = socket.socket()
    if self.secure:
      self.lsock = self.context.wrap_socket(so, server_side=True)
    else:
      self.lsock = socket.socket()
    self.lsock.bind((self.ip, self.port))
    self.lsock.listen()
    print('TCP server %s|%s started on port %s' % (user, device, self.port))
    with AES(self.md5_password) as aes:
      while not self.lsock._closed:
        try:
          sock = self.lsock.accept()[0]
        except:
          continue
        msg = b''
        sock.settimeout(1)
        while msg != b'*model*':
          try:
            msg = msg + sock.recv(1024)
            sock.settimeout(0.1)
            if msg == b'':
              break
            if msg == b'*model*':
              sock.sendall((user + '|' + device).encode('utf-8'))
              print('Discovered by %s' % sock.getpeername()[0])
          except:
            plain_message = b''
            if len(msg) >= 32 and len(msg) % 16 == 0:
              plain_message = aes.Decipher(msg[0:16], msg[16:])
            if (plain_message + b'\n').split(b'\n', 1)[1][:32] == self.md5_password:
              sock.settimeout(5)
              sock.send(b'Write the binary now...')
              print('%s connected' % sock.getpeername()[0])
              fileinfo = plain_message.rsplit(b'\n', 3)[1:]
              filepath = root.rstrip('\\') + (root and '\\') + fileinfo[2].rstrip(b'\x00').decode('utf-8').replace('/', '\\').lstrip('\\')
              filesize = int(fileinfo[0].decode('utf-8'))
              filedate = float(fileinfo[1].decode('utf-8')) / 1000
              Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
              c = 0
              while os.path.exists(ren(filepath, c)):
                c += 1
              filepath = ren(filepath, c)
              file = open(filepath, 'wb')
              print('Receiving %s...' % fileinfo[2].rstrip(b'\x00').decode('utf-8'))
              copied = 0
              while copied < filesize:
                bloc = sock.recv(1024*1024)
                copied += len(bloc)
                file.write(bloc)
              file.close()
              os.utime(filepath, (time.time(), filedate))
              sock.send(b'finished')
              print('File %s received' % filepath)
              msg = b''
              sock.settimeout(1) 
            else:
              break
        sock.close()
    self.lsock.close()
    print('TCP server %s|%s stopped' % (user, device))

  def StartReceiving(self, user, device, root):
    receiver_thread = threading.Thread(target=self._StartReceiving, args=(user, device, root))
    receiver_thread.start()

  def StopReceiving(self):
    self.lsock.close()


if __name__ == '__main__':
  formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=50, width=119)
  CustomArgumentParser = partial(argparse.ArgumentParser, formatter_class=formatter)
  parser = CustomArgumentParser()
  subparsers = parser.add_subparsers(dest='command', parser_class=CustomArgumentParser)
  send_parser = subparsers.add_parser('send', aliases=['s'], help='Sends a file to a MiXplorer TCP server')
  send_parser.add_argument('--ip', '-i', metavar='PHONE_IP', help='ip of the phone (otherwise will choose the first responding device inside the /24 subnet)', default='')
  send_parser.add_argument('--port', '-p', metavar='TCP_PORT', help='port of the TCP server on the phone (otherwise set to 5225)', type=int, default=5225)
  send_parser.add_argument('--password', '-w', metavar='TCP_PASSWORD', help='password of the TCP server on the phone (otherwise set to none)', default='')
  send_parser.add_argument('--secure', '-s', help='enables secure communication with the TCP server on the phone (otherwise not activated)', action='store_true')
  send_parser.add_argument('--dest', '-d', metavar='FILE_DESTPATH', help='absolute or relative path of the file on the phone (otherwise set to just the name of the file)', default='')
  send_parser.add_argument('src', metavar='FILE_SRCPATH', help='list of pathes to the file/folder on the computer', nargs='+')
  receive_parser = subparsers.add_parser('receive', aliases=['r'], help='Receives files from MiXplorer TCP "send to..."')
  receive_parser.add_argument('--port', '-p', metavar='TCP_PORT', help='port of the TCP server on the computer (otherwise set to 5225)', type=int, default=5225)
  receive_parser.add_argument('--password', '-w', metavar='TCP_PASSWORD', help='password of the TCP server on the computer (otherwise set to none)', default='')
  receive_parser.add_argument('--user', '-u', metavar='TCP_USER', help='username of the TCP server on the computer (otherwise set to none)', default='')
  receive_parser.add_argument('--device', '-d', metavar='TCP_DEVICE', help='devicename of the TCP server on the computer (otherwise set to PC)', default='PC')
  receive_parser.add_argument('--secure', '-s', help='enables secure communication with the phone (otherwise not activated, needs cert.pem and key.pem)', action='store_true')
  receive_parser.add_argument('--kpassword', '-k', metavar='TLS_KPASSWORD', help='password used for encrypting key.pem (used in conjunction with --secure)')
  receive_parser.add_argument('--root', '-r', metavar='FILE_ROOTPATH', help='root path of file storage on the computer (otherwise set to none)', default='')
  args = parser.parse_args()
  if not args.command:
    parser.print_help()
    exit()
  if args.command.lower() in ('receive', 'r'):
    if args.secure and not args.kpassword:
      receive_parser.error("with --secure, the following argument is required: --kpassword/-k")
  mtcp = MiXplorerTCP(args.port, args.password, args.secure, args.kpassword if args.command.lower() == 'r' else None)
  if args.command.lower() in ('send', 's'):
    if args.ip:
      mtcp.Sendto(args.ip, args.src, args.dest)
    else:
      mtcp.SendtoFirst(args.src, args.dest)
  elif args.command in ('receive', 'r'):
    mtcp.StartReceiving(args.user, args.device, args.root)
    print('Press S to stop receiving')
    k = b''
    while k.upper() != b'S':
      k = msvcrt.getch()
      if k == b'\xe0':
        k = msvcrt.getch() and b''
    mtcp.StopReceiving()