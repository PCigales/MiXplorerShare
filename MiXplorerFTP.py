import ctypes, ctypes.wintypes
import hashlib
import base64
import textwrap
import shutil
import os, os.path
from pathlib import Path
import socket
import ssl
import time
import calendar
import threading
import argparse
from functools import partial
import msvcrt

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))


wcrypt = ctypes.WinDLL('crypt32', use_last_error=True)
ncrypt = ctypes.WinDLL('ncrypt', use_last_error=True)
iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32',  use_last_error=True)
byref = ctypes.byref
HANDLE = ctypes.wintypes.HANDLE
LPCWSTR = ctypes.wintypes.LPCWSTR
LPWSTR = ctypes.wintypes.LPWSTR
ULONG = ctypes.wintypes.ULONG
DWORD = ctypes.wintypes.DWORD
WORD = ctypes.wintypes.WORD
PVOID = ctypes.c_void_p
LPVOID = ctypes.wintypes.LPVOID
POINTER = ctypes.POINTER
class CRYPT_KEY_PROV_INFO(ctypes.Structure):
  _fields_ = [('pwszContainerName', LPWSTR), ('pwszProvName', LPWSTR), ('dwProvType', DWORD), ('dwFlags', DWORD), ('cProvParam', DWORD), ('rgProvParam', PVOID), ('dwKeySpec', DWORD)]
class CERT_EXTENSIONS(ctypes.Structure):
  _fields_ = [('cExtension', DWORD), ('rgExtension', HANDLE)]
class SYSTEMTIME(ctypes.Structure):
  _fields_ = [('wYear', WORD), ('wMonth', WORD), ('wDayOfWeek', WORD), ('wDay', WORD), ('wHour', WORD), ('WMinute', WORD), ('WSecond', WORD), ('WMilliseconds', WORD)]
P_SYSTEMTIME = POINTER(SYSTEMTIME)
class CRYPT_INTEGER_BLOB(ctypes.Structure):
  _fields_ = [('cbData', DWORD), ('pbData', PVOID)]
class CERT_CONTEXT(ctypes.Structure):
  _fields_ = [('dwCertEncodingType', DWORD), ('pbCertEncoded', PVOID), ('cbCertEncoded', DWORD), ('pCertInfo', PVOID), ('hCertStore', HANDLE)]
P_CERT_CONTEXT = POINTER(CERT_CONTEXT)

class RSASelfSigned():

  def __init__(self, name, years):
    self.name = name
    self.years = years
    self.ready = threading.Event()

  def Generate(self):
    pcbEncoded = DWORD(0)
    wcrypt.CertStrToNameW(DWORD(1), LPCWSTR('CN=' + self.name), DWORD(2), None, None, byref(pcbEncoded), None)
    pSubjectIssuerBlob = CRYPT_INTEGER_BLOB()
    pSubjectIssuerBlob.cbData = DWORD(pcbEncoded.value)
    pSubjectIssuerBlob.pbData = ctypes.cast(ctypes.create_string_buffer(pcbEncoded.value), PVOID)
    wcrypt.CertStrToNameW(DWORD(1), LPCWSTR('CN=' + self.name), DWORD(2), None, PVOID(pSubjectIssuerBlob.pbData), byref(pcbEncoded), None)
    phProvider = HANDLE(0)
    ncrypt.NCryptOpenStorageProvider(byref(phProvider), LPCWSTR('Microsoft Software Key Storage Provider'), DWORD(0))
    phKey = HANDLE(0)
    ncrypt.NCryptCreatePersistedKey(phProvider, byref(phKey), LPCWSTR('RSA'), None, DWORD(1), DWORD(0))
    ncrypt.NCryptSetProperty(phKey, LPCWSTR('Export Policy'), byref(ULONG(3)), 4, ULONG(0x80000000))
    ncrypt.NCryptSetProperty(phKey, LPCWSTR('Length'), byref(DWORD(2048)), 4, ULONG(0x80000000))
    ncrypt.NCryptFinalizeKey(phKey, DWORD(0x40))
    pKeyProvInfo = CRYPT_KEY_PROV_INFO()
    pKeyProvInfo.pwszContainerName = LPWSTR('CN=' + self.name)
    pKeyProvInfo.pwszProvName = LPWSTR('Microsoft Software Key Storage Provider')
    pKeyProvInfo.dwProvType = DWORD(0x01)
    pKeyProvInfo.dwFlags = DWORD(0x40)
    pKeyProvInfo.cProvParam = DWORD(0)
    pKeyProvInfo.rgProvParam = PVOID(0)
    pKeyProvInfo.dwKeySpec = DWORD(1)
    pSignatureAlgorithm = None
    pStartTime = P_SYSTEMTIME(SYSTEMTIME())
    kernel32.GetSystemTime(pStartTime)
    pEndTime = P_SYSTEMTIME(SYSTEMTIME())
    ctypes.memmove(pEndTime, pStartTime, ctypes.sizeof(SYSTEMTIME))
    pEndTime.contents.wYear += self.years
    if pEndTime.contents.wMonth == 2 and pEndTime.contents.wDay == 29:
      pEndTime.contents.wDay = 28
    pExtensions = CERT_EXTENSIONS()
    pExtensions.cExtension = 0
    pExtensions.rgExtension = PVOID(0)
    wcrypt.CertCreateSelfSignCertificate.restype = P_CERT_CONTEXT
    pCertContext = wcrypt.CertCreateSelfSignCertificate(phKey, pSubjectIssuerBlob, DWORD(0), pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)
    self.cert = ctypes.string_at(pCertContext.contents.pbCertEncoded, pCertContext.contents.cbCertEncoded)
    pcbResult = DWORD(0)
    ncrypt.NCryptExportKey(phKey, None, LPCWSTR('PKCS8_PRIVATEKEY'), None, None, 0, byref(pcbResult), DWORD(0x40))
    pbOutput = ctypes.create_string_buffer(pcbResult.value)
    ncrypt.NCryptExportKey(phKey, None, LPCWSTR('PKCS8_PRIVATEKEY'), None, pbOutput, pcbResult, byref(pcbResult), DWORD(0x40))
    self.key = bytes(pbOutput)
    ncrypt.NCryptFreeObject(phProvider)
    ncrypt.NCryptDeleteKey(phKey, DWORD(0x40))
    wcrypt.CertFreeCertificateContext(pCertContext)

  def GetPEM(self):
    return ('-----BEGIN CERTIFICATE-----\r\n' + '\r\n'.join(textwrap.wrap(base64.b64encode(self.cert).decode('utf-8'), 64)) + '\r\n-----END CERTIFICATE-----\r\n', '-----BEGIN PRIVATE KEY-----\r\n' + '\r\n'.join(textwrap.wrap(base64.b64encode(self.key).decode('utf-8'), 64)) + '\r\n-----END PRIVATE KEY-----\r\n')

  def PipePEM(self, certname, keyname):
    pipe_c = HANDLE(kernel32.CreateNamedPipeW(LPCWSTR('\\\\.\\pipe\\' + certname + ('.pem' if certname[:4].lower() != '.pem' else '')), DWORD(0x00000002), DWORD(0), DWORD(1), DWORD(0x100000), DWORD(0x100000), DWORD(0), HANDLE(0)))
    pipe_k = HANDLE(kernel32.CreateNamedPipeW(LPCWSTR('\\\\.\\pipe\\' + keyname + ('.pem' if keyname[:4].lower() != '.pem' else '')), DWORD(0x00000002), DWORD(0), DWORD(1), DWORD(0x100000), DWORD(0x100000), DWORD(0), HANDLE(0)))
    self.ready.set()
    for (p, v) in zip((pipe_c, pipe_k), (t.encode('utf-8') for t in self.GetPEM())):
      kernel32.ConnectNamedPipe(p, LPVOID(0))
      n = DWORD(0)
      kernel32.WriteFile(p, ctypes.cast(v, PVOID), DWORD(len(v)), byref(n), LPVOID(0))
      kernel32.FlushFileBuffers(p)
      kernel32.CloseHandle(p)

  def TPipePEM(self, certname, keyname):
    pipe_thread = threading.Thread(target=self.PipePEM, args=(certname, keyname))
    pipe_thread.start()
    self.ready.wait()

  def __enter__(self):
    self.Generate()
    return self

  def __exit__(self, type, value, traceback):
    pass


class MiXplorerShare():

  def __init__(self, port, device, user, password, secure=False, kpassword=None, client=True, verbose=False):
    try:
      self.ip = socket.gethostbyname(socket.gethostname())
    except:
      try:
        self.ip = socket.gethostbyname(socket.getfqdn())
      except:
        self.ip = None
    self.port = port
    self.device = device
    self.user = user
    self.password = password
    self.secure = secure
    self.client = client
    self.verbose = verbose
    self.lsock = None
    self.c_so = None
    self.buf = b''
    if secure:
      if client:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
      else:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
          self.context.load_cert_chain(os.path.join(SCRIPT_PATH, 'cert.pem'), os.path.join(SCRIPT_PATH, 'key.pem'), password=kpassword)
        except:
          print('Could not load cert.pem and key.pem'+ (' with password ' + kpassword if kpassword else ''))
          print('Will use an own generated self signed certificate')
          with RSASelfSigned('MiXplorerShare', 1) as cert:
            id = base64.b32encode(os.urandom(10)).decode('utf-8')
            cert.TPipePEM('cert' + id, 'key' + id)
            self.context.load_cert_chain(r'\\.\pipe\cert%s.pem' % id, r'\\.\pipe\key%s.pem' % id)

  def _rep(self):
    code = b''
    msg = b''
    try:
      while True:
        while b'\r\n' in self.buf:
          l, self.buf = self.buf.split(b'\r\n', 1)
          if code:
            if len(l) >= 3:
              code_ = l[:3]
              if min(code_) >= 48 and max(code_) <= 57:
                if code_ == code and l[3:4] == b' ':
                  msg += b'\r\n' + l[4:].lstrip()
                  return (code.decode('utf-8'), msg.decode('utf-8'))
                else:
                  raise
            msg += b'\r\n' + l.lstrip()
          else:
            if len(l) < 4:
              raise
            code = l[:3]
            if min(code) < 48 or max(code) > 57:
              raise
            msg += l[4:].lstrip()
            if l[3:4] == b' ':
              return (code.decode('utf-8'), msg.decode('utf-8'))
        b = self.c_so.recv(4096)
        if b:
          self.buf += b
        else:
          raise
    except:
      code = msg = None
      self.buf = b''
      return (None, None)
    finally:
      if self.verbose:
        if code is None:
          print('...< Unprocessable response')
        else:
          print('...<', code.decode('utf-8'), '\r\n...< '.join(msg.decode('utf-8').split('\r\n')))

  def _cmd(self):
    try:
      while not b'\r\n' in self.buf:
        b = self.c_so.recv(4096)
        if b:
          self.buf += b
        else:
          raise
      msg, self.buf = self.buf.split(b'\r\n', 1)
      msg = msg.decode('utf-8')
    except:
      if self.verbose and not self.c_so._closed:
        print('< Unprocessable command')
      self.buf = b''
      return (None, None)
    if self.verbose:
      print('<', msg)
    return msg.partition(' ')[::2]

  def _send(self, m):
    try:
      self.c_so.sendall((m + '\r\n').encode('utf-8'))
    except:
      if self.verbose:
        print('> Unsendable command', m)
      return False
    if self.verbose:
      print('>', '\r\n> '.join(m.split('\r\n')))
    return True

  def Sendto(self, ip, src, root=''):
    if not self.client:
      return False
    ren = lambda f, c: (' (%d)' % c if c else '').join(os.path.splitext(f))
    is_pp = lambda c: c[0] == '1' if c else False
    is_pc = lambda c: c[0] == '2' if c else False
    is_pi = lambda c: c[0] == '3' if c else False
    self.buf = b''
    src_list = []
    if not isinstance(src, (list, tuple)):
      src = (src,)
    for s in map(os.path.abspath, src):
      if os.path.isdir(s):
        src_list.append(list([os.path.relpath(e[0], os.path.dirname(s)), list(os.path.join(e[0], f) for f in e[2]), os.path.getmtime(e[0])] for e in os.walk(s)))
      else:
        src_list.append([['.', (s,), 0],])
    print('Initiating the transfer to %s:%s...' % (ip, self.port))
    try:
      if self.c_so is None:
        c_soc = socket.socket()
        c_soc.settimeout(5)
        c_soc.connect((ip, self.port))
        self.c_so = c_soc
        if not is_pc(self._rep()[0]):
          raise
      else:
        c_soc = self.c_so
      if self.secure:
        if not self._send('AUTH TLS'):
          raise
        if not is_pc(self._rep()[0]):
          print('Could not initiate TLS command channel')
          raise
        self.c_so = self.context.wrap_socket(c_soc, server_side=False)
      if not self._send('USER ' + self.user):
        raise
      if not is_pi(self._rep()[0]):
        print('Access to user %s denied' % self.user)
        raise
      if not self._send('PASS ' + self.password):
        raise
      if not is_pc(self._rep()[0]):
        print('Password %s refused' % self.password)
        raise
      if self.secure:
        if not self._send('PBSZ 0'):
          raise
        if not is_pc(self._rep()[0]):
          print('Could not initiate TLS data channel')
          raise
        if not self._send('PROT P'):
          raise
        if not is_pc(self._rep()[0]):
          print('Could not initiate TLS data channel')
          raise
    except:
      print('Could not connect to %s:%s' % (ip, self.port))
      try:
        c_so.close()
      except:
        pass
      self.c_so = None
      return False
    try:
      if not self._send('OPTS UTF8 ON'):
        raise
      if not is_pc(self._rep()[0]):
        raise
      if not self._send('PWD'):
        raise
      c, r = self._rep()
      if not is_pc(c):
        raise
      if root:
        root = ('/' + r.split('"', 1)[1].rsplit('"', 1)[0].lstrip('/')).rstrip('/') + '/' + root.replace('\\', '/').strip('/')
        # root = (('/' + r.split('"', 1)[1].rsplit('"', 1)[0].lstrip('/')).rstrip('/') + '/' + root.replace('\\', '/').strip('/')).replace('""', '"')
        if not self._send('CWD ' + root):
          raise
        if not is_pc(self._rep()[0]):
          print('Access to the specified root path denied')
          raise
      else:
        root = ('/' + r.split('"', 1)[1].rsplit('"', 1)[0].lstrip('/')).rstrip('/')
        # root = ('/' + r.split('"', 1)[1].rsplit('"', 1)[0].lstrip('/')).rstrip('/').replace('""', '"')
      if not self._send('TYPE I'):
        raise
      if not is_pc(self._rep()[0]):
        raise
    except:
      print('Could not initiate the transfer')
      try:
        self.c_so.close()
      except:
        pass
      self.c_so = None
      return False
    try:
      if not self._send('PASV'):
        raise
      c, r = self._rep()
      if not is_pc(c):
        raise
      a = r.split('(')[1].split(')')[0].split(',')
      d_so = socket.create_connection(('%s.%s.%s.%s' % (*a[0:4],), int(a[4]) * 256 + int(a[5])))
      d_so.settimeout(5)
      if not self._send('LIST'):
        raise
      if self.secure:
        d_soc = d_so
        d_so = self.context.wrap_socket(d_soc, server_side=False)
      if not is_pp(self._rep()[0]):
        raise
      lst = b''
      while True:
        b = d_so.recv(4096)
        if b:
          lst += b
        else:
          break
      d_so.close()
      if not is_pc(self._rep()[0]):
        raise
      lst = list(e.split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].lstrip(b' ').split(b' ', 1)[1].decode('utf-8') for e in lst.split(b'\r\n') if e)
    except:
      print('Could not retrieve the root content')
      try:
        d_so.close()
      except:
        pass      
      try:
        self.c_so.close()
      except:
        pass
      self.c_so = None
      return False
    cdir = '.'
    sfold = ''
    for sf in src_list:
      for s in sf:
        try:
          d = os.path.relpath(s[0], cdir)
          cdir = s[0]
          if sfold:
            s[0] = '\\'.join((sfold, s[0].split('\\', 1)[1]))
          p = ('%s/%s' % (root, s[0].replace('\\', '/'))) if s[0] != '.' else root
          if cdir != '.':
            e, f = p.rpartition('/')[::2]
            e = e or '/'
            if not '\\' in cdir:
              if f in lst:
                c = 0
                while ren(f, c) in lst:
                  c += 1
                sfold = ren(f, c)
                s[0] = sfold
                p = '%s/%s' % (root, sfold)
                f = sfold
            if '..' in d:
              if not self._send('CWD ' + e):
                raise
              if not is_pc(self._rep()[0]):
                raise
            if not self._send('MKD ' + p):
              raise
            if not is_pc(self._rep()[0]):
              raise
            lst.append(f)
            if not self._send('CWD ' + p):
              raise
            if not is_pc(self._rep()[0]):
              raise
            print('Folder "%s" created in "%s"' % (f, e))
        except:
          print('Could not create "%s"' % s[0].replace('\\', '/'))
          sf.clear()
          break
        for f in s[1]:
          try:
            fn = os.path.basename(f)
            if s[0] == '.':
              if fn in lst:
                c = 0
                while ren(fn, c) in lst:
                  c += 1
                fn = ren(fn, c)
              lst.append(fn)
            if not self._send('PASV'):
              raise
            c, r = self._rep()
            if not is_pc(c):
              raise
            a = r.split('(')[1].split(')')[0].split(',')
            d_so = socket.create_connection(('%s.%s.%s.%s' % (*a[0:4],), int(a[4]) * 256 + int(a[5])))
            d_so.settimeout(5)
            if not self._send('REST 0'):
              raise
            if not is_pi(self._rep()[0]):
              raise
            fp = '/'.join((p, fn))
            if not self._send('STOR ' + fp):
              raise
            if self.secure:
              d_soc = d_so
              d_so = self.context.wrap_socket(d_soc, server_side=False)
            if not is_pp(self._rep()[0]):
              raise
            try:
              file = open(f, 'rb')
            except:
              print('Could not open the file %s' % f)
              raise
            try:
              shutil.copyfileobj(file, d_so.makefile('wb'))
            except:
              raise
            finally:
              file.close()
            d_so.close()
            if not is_pc(self._rep()[0]):
              raise
          except:
            print('Could not transfer "%s"' % f)
            try:
              d_so.close()
            except:
              pass
            continue
          print('File "%s" transfered as "%s"' % (f, fp))
          try:
            if not self._send('MFMT ' + time.strftime('%Y%m%d%H%M%S', time.gmtime(os.path.getmtime(f))) + ' ' + fp):
              raise
            if not is_pc(self._rep()[0]):
              raise
          except:
            print('Could not set date of "%s"' % fp)
            continue
      if cdir != '.':
        try:
          if not self._send('CWD ' + (root or '/')):
            raise
          if not is_pc(self._rep()[0]):
            raise
          cdir = '.'
        except:
          print('Could not go back to root')
          try:
            self.c_so.close()
          except:
            pass
          self.c_so = None
          return False
      sfold = ''
    for sf in src_list:
      for s in reversed(sf):
        if s[0] != '.':
          try:
            if self._send('MFMT ' + time.strftime('%Y%m%d%H%M%S', time.gmtime(s[2])) + ' ' + ('%s/%s' % (root, s[0].replace('\\', '/')))):
              self._rep()
          except:
            pass
    try:
      if self._send('QUIT'):
        self._rep()
    except:
      pass
    try:
      self.c_so.close()
    except:
      pass
    self.c_so = None
    return True

  def SendtoFirst(self, src, root=''):
    if not self.client:
      return False
    ip_p, ip_h = self.ip.rsplit('.', 1)
    ip_arp = []
    print('Looking for a device running a server on port %s...' % self.port, end ='', flush=True)
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
      self.c_so = socket.socket()
      self.c_so.settimeout(1)
      try:
        self.c_so.connect((ip, self.port))
      except:
        self.c_so = None
        continue
      try:
        print(' ')
        if self._rep()[0] == '220':
          if self._send('MODEL'):
            c, r = self._rep()
            if c == '222':
              print('Found %s' % r[:-5].replace('\r\n', ' — '))
              if self.Sendto(ip, src, root) == False:
                print('Looking for a device running a server on port %s...' % self.port, end ='', flush=True)
                raise
              return
      except:
        pass
    print('\r\nNo device allowing successfull transfer was found')

  def _StartReceiving(self, root):
    try:
      self.lsock = socket.create_server((self.ip, self.port))
    except:
      print('Could not start share server on port %s' % self.port)
      return
    print('Share server %s — ftp%s://%s:%s — %s — %s started' % (self.device, ('es' if self.secure else ''), self.ip, self.port, self.user, ('-1' if self.password else '0')))
    while not self.lsock._closed:
      try:
        self.buf = b''
        c_soc = self.lsock.accept()[0]
        print('Connexion from %s' % c_soc.getpeername()[0])
        self.c_so = c_soc
        if not self._send('220 ---------- Welcome to %s - MiXplorerShare ----------' % self.device):
          raise
      except:
        try:
          self.c_so.close()
        except:
          pass
        continue
      con = 0
      pas = False
      prot = False
      cdir = '\\'
      rest = 0
      ct = time.time()
      cdt = 0
      while not self.c_so._closed and not self.lsock._closed:
        self.c_so.settimeout(None)
        c, p = self._cmd()
        if c is None:
          self.c_so.close()
          continue
        self.c_so.settimeout(5)
        c = c.upper()
        cdt = time.time() - ct
        try:
          if c == 'MODEL':
            print('Discovered by %s' % self.c_so.getpeername()[0])
            self._send('222-%s\r\n ftp%s://%s:%s\r\n %s|\r\n %s\r\n222 End' % (self.device, ('es' if self.secure else ''), self.ip, self.port, self.user, ('-1' if self.password else '0')))
          elif c == 'QUIT':
            self._send('221 QUIT Goodbye!')
            self.c_so.close()
          elif c == 'AUTH' and p.upper() == 'TLS':
            if self.secure:
              self._send('234 AUTH Enabling TLS/SSL...')
              self.c_so = self.context.wrap_socket(c_soc, server_side=True)
            else:
              self._send('502 AUTH Auth type not enabled on the server')
          elif c == 'PBSZ':
            if self.secure:
              self._send('200 PBSZ The SSL buffer size was set to ' + p)
            else:
              self._send('503 PBSZ SSL is not enabled')
          elif c == 'PROT' and p.upper() in ('P', 'PRIVATE'):
            if self.secure:
              prot = True
              self._send('200 PROT Protection level enabled')
            else:
              self._send('503 PROT Insecure Connection!')
          elif c == 'REIN':
            con = 0
            pas = False
            prot = False
            rest = 0
            cdir = '\\'
            self._send('220 REIN user logged out')
          elif c == 'USER':
            if p == self.user:
              self._send('331 USER send the password')
              con = max(con, 1)
            else:
              self._send('530 USER authentication failed!')
          elif c == 'PASS':
            if p == self.password and con >= 1:
              self._send('230 PASS access granted')
              con = 2
            else:
              self._send('530 PASS authentication failed!')
          elif c == 'FEAT':
            self._send('211-Features supported\r\n UTF8\r\n MFMT\r\n REST STREAM\r\n211 End')
          elif c == 'SYST':
            self._send('215 WINDOWS Type: L8')
          elif con != 2:
            self._send('530 login with user-pass')
            continue
          elif c == 'OPTS' and p.upper() == 'UTF8 ON':
            self._send('200 OPTS Done')
          elif c == 'PWD':
            if cdt > 2:
              cdir = '\\'
            # self._send('257 PWD "%s"' % cdir.replace('\\', '/').replace('"', '""'))
            self._send('257 PWD "%s"' % cdir.replace('\\', '/'))
          elif c == 'CWD':
            excdir = cdir
            cdir = os.path.normpath(os.path.join(cdir, p.replace('/', '\\')))
            if os.path.isdir(os.path.join(root, cdir.strip('\\'))):
              self._send('250 CWD Done')
            else:
              cdir = excdir
              self._send('550 path does not exist')
          elif c == 'MD5':
            self._send('251 MD5 ' + hashlib.md5(p.encode('utf-8')).hexdigest())
          elif c == 'MKD':
            try:
              Path(os.path.join(root, os.path.join(cdir, p.replace('/', '\\')).strip('\\'))).mkdir(parents=True, exist_ok=True)
              self._send('257 MKD Done')
            except:
              self._send('550 MKD Failed')
          elif c == 'TYPE':
            self._send('200 TYPE set to: ' + ('ASCII' if p[:1] in ('A', 'a') else 'BINARY'))# fake
          elif c == 'REST':
            try:
              rest = int(p)
            except:
              self._send('550 REST offset not valid!')
              continue
            if rest >= 0:
              self._send('350 REST offset (%i)' % rest)
            else:
              rest = 0
              self._send('550 REST offset not valid!')
          elif c == 'PASV':
            self._send('227 PASV Passive mode (%s,%s,%s)' % (self.ip.replace('.', ','), self.port // 256, self.port % 256))
            pas = True
          elif c == 'STOR' or c == 'APPE':
            if not pas:
              self._send('425 %s could not open socket' % c)
              continue
            restex = rest
            rest = 0
            f = os.path.join(root, os.path.join(cdir, p.replace('/', '\\')).strip('\\'))
            try:
              file = open(f, ('wb' if c == 'STOR' else 'ab') if restex == 0 else 'r+b')
            except:
              print('Could not open the file %s' % f)
              self._send('550 path does not exist')
              continue
            self._send('150 %s socket ready' % c)
            if restex != 0:
              file.seek(restex)
            pas = False
            try:
              d_soc = self.lsock.accept()[0]
              d_so = d_soc
              if prot:
                d_so = self.context.wrap_socket(d_soc, server_side=True)
              shutil.copyfileobj(d_so.makefile('rb'), file)
            except:
              print('Could not receive the file %s' % f)
              self._send('425 %s could not open socket' % c)
              continue
            finally:
              try:
                d_so.close()
              except:
                pass
              file.close()
            self._send('226 %s Done' % c)
            print('File "%s" %s "%s"' % (p, ('received as' if c == 'STOR' else 'appended to'), f) + ((' at position %i' % restex) if restex else ''))
          elif c == 'MFMT':
            try:
              m, f = p.split(' ', 1)
              m = calendar.timegm(time.strptime(m, '%Y%m%d%H%M%S'))
              f = os.path.join(root, os.path.join(cdir, f.replace('/', '\\')).strip('\\'))
              os.utime(f, (time.time(), m))
            except:
              self._send('500 MFMT Failed')
              pass
            self._send('213 MFMT ' + p.replace(' ', '; ', 1))
          elif c == 'LIST':
            if not pas:
              self._send('425 LIST could not open socket')
              continue
            self._send('150 LIST ASCII Opening...')
            pas = False
            f = os.path.join(root, os.path.join(cdir, p.replace('/', '\\')).strip('\\'))
            try:
              if os.path.isdir(f):
                lst = ''.join('%srw-r--r-- 1 00000 00000 %12s %s %s\r\n' % (('d' if e.is_dir() else '-'), es.st_size, time.strftime('%b %d  %Y', time.gmtime(es.st_mtime)), e.name) for e in os.scandir(f) for es in (e.stat(), ))
              elif os.path.isfile(f):
                lst = ''.join('-rw-r--r-- 1 00000 00000 %12s %s %s\r\n' % (es.st_size, time.strftime('%b %d  %Y', time.gmtime(es.st_mtime)), os.path.basename(f)) for es in (os.stat(f), ))
              else:
                raise
            except:
              lst = ''
            try:
              d_soc = self.lsock.accept()[0]
              d_so = d_soc
              if prot:
                d_so = self.context.wrap_socket(d_soc, server_side=True)
              d_so.sendall(lst.encode('utf-8'))
            except:
              self._send('425 LIST could not open socket\r\n')
              continue
            finally:
              try:
                d_so.close()
              except:
                pass
            self._send('226 LIST Done')
          elif c == '':
            self._send('502 No command!')
          else:
            self._send('502 %s not supported!' % c)
        except:
          continue
        ct = time.time()
      try:
        self.c_so.close()
      except:
        pass
    print('Share server stopped')

  def StartReceiving(self, root):
    if self.client:
      return False
    receiver_thread = threading.Thread(target=self._StartReceiving, args=(root,))
    receiver_thread.start()
    return True

  def StopReceiving(self):
    try:
      self.c_so.close()
    except:
      pass
    try:
      self.lsock.close()
    except:
      pass


if __name__ == '__main__':
  formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=50, width=119)
  CustomArgumentParser = partial(argparse.ArgumentParser, formatter_class=formatter)
  parser = CustomArgumentParser()
  subparsers = parser.add_subparsers(dest='command', parser_class=CustomArgumentParser)
  send_parser = subparsers.add_parser('send', aliases=['s'], help='Sends files to a MiXplorer FTP server')
  send_parser.add_argument('--ip', '-i', metavar='PHONE_IP', help='ip of the phone (otherwise will choose the first responding device inside the arp table then the /24 subnet)', default='')
  send_parser.add_argument('--port', '-p', metavar='FTP_PORT', help='port of the FTP server on the phone (otherwise set to 2121)', type=int, default=2121)
  send_parser.add_argument('--user', '-u', metavar='FTP_USER', help='username of the FTP server on the computer (otherwise set to Admin)', default='Admin')
  send_parser.add_argument('--password', '-w', metavar='FTP_PASSWORD', help='password of the FTP server on the phone (otherwise set to none)', default='')
  send_parser.add_argument('--secure', '-s', help='enables secure communication with the FTP server on the phone (otherwise not activated, "Explicit TLS" must be enabled in the settings of the FTP server)', action='store_true')
  send_parser.add_argument('--root', '-r', metavar='FILE_ROOTPATH', help='relative root path of file storage on the phone (otherwise let to the default working directory)', default='')
  send_parser.add_argument('--verbose', '-v', help='increases the verbosity', action='store_true')
  send_parser.add_argument('src', metavar='FILE_SRCPATH', help='list of pathes to files/folders on the computer', nargs='+')
  receive_parser = subparsers.add_parser('receive', aliases=['r'], help='Receives files from MiXplorer FTP "send to..."')
  receive_parser.add_argument('--device', '-d', metavar='FTP_DEVICE', help='devicename of the FTP server on the computer (otherwise set to PC)', default='PC')
  receive_parser.add_argument('--port', '-p', metavar='FTP_PORT', help='port of the FTP server on the computer (otherwise set to 2121)', type=int, default=2121)
  receive_parser.add_argument('--user', '-u', metavar='FTP_USER', help='username of the FTP server on the computer (otherwise set to Admin)', default='Admin')
  receive_parser.add_argument('--password', '-w', metavar='FTP_PASSWORD', help='password of the FTP server on the computer (otherwise set to none)', default='')
  receive_parser.add_argument('--secure', '-s', help='enables secure communication with the phone (otherwise not activated, cert.pem and key.pem can be provided)', action='store_true')
  receive_parser.add_argument('--kpassword', '-k', metavar='TLS_KPASSWORD', help='password used for encrypting key.pem (used in conjunction with --secure if key.pem needs one, otherwise none)', default=None)
  receive_parser.add_argument('--root', '-r', metavar='FILE_ROOTPATH', help='root path of file storage on the computer (otherwise set to the current working directory)', default='')
  receive_parser.add_argument('--verbose', '-v', help='increases the verbosity', action='store_true')
  args = parser.parse_args()
  if not args.command:
    parser.print_help()
    exit()
  msh = MiXplorerShare(args.port, args.device if args.command.lower() == 'r' else None, args.user, args.password, args.secure, args.kpassword if args.command.lower() == 'r' else None, args.command.lower() == 's', args.verbose)
  if args.command.lower() in ('send', 's'):
    if args.ip:
      msh.Sendto(args.ip, args.src, args.root)
    else:
      msh.SendtoFirst(args.src, args.root)
  elif args.command in ('receive', 'r'):
    msh.StartReceiving(os.path.abspath(args.root))
    print('Press S to stop receiving')
    k = b''
    while k.upper() != b'S':
      k = msvcrt.getch()
      if k == b'\xe0':
        k = msvcrt.getch() and b''
    msh.StopReceiving()