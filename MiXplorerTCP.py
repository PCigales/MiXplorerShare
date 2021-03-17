import ctypes, ctypes.wintypes
import hashlib
import shutil
import os.path
import random
import socket

random.seed()

def AESCipher(plain_text, key, iv):
  HANDLE = ctypes.wintypes.HANDLE
  pointer = ctypes.pointer
  byref = ctypes.byref
  LPCWSTR = ctypes.wintypes.LPCWSTR
  ULONG = ctypes.wintypes.ULONG
  DWORD = ctypes.wintypes.DWORD
  bcrypt = ctypes.WinDLL('bcrypt', use_last_error=True)
  class BCRYPT_KEY_DATA_BLOB_HEADER(ctypes.Structure):
    _fields_ = [('dwMagic', ULONG), ('dwVersion', ULONG), ('cbKeyData', ULONG)]
  BCryptProviderH = HANDLE(0)
  bcrypt.BCryptOpenAlgorithmProvider(byref(BCryptProviderH), LPCWSTR('AES'), LPCWSTR(None), ULONG(0))
  BCryptKeyL = DWORD(0)
  BCryptKeyLC = ULONG(0)
  bcrypt.BCryptGetProperty(BCryptProviderH, LPCWSTR('ObjectLength'), byref(BCryptKeyL), ULONG(ctypes.sizeof(BCryptKeyL)), byref(BCryptKeyLC), ULONG(0))
  BCryptKeyH = HANDLE(0)
  BCryptKey = ctypes.create_string_buffer(BCryptKeyL.value)
  BCryptKeyI = ctypes.create_string_buffer(key)
  bcrypt.BCryptGenerateSymmetricKey(BCryptProviderH, byref(BCryptKeyH), byref(BCryptKey), ULONG(BCryptKeyL.value), BCryptKeyI, ULONG(32), ULONG(0))
  BCryptInput = ctypes.create_string_buffer(plain_text)
  BCryptIV = ctypes.create_string_buffer(iv)
  BCryptOutput = ctypes.create_string_buffer(len(BCryptInput) - 1)
  BCryptOuputS = ULONG(0)
  bcrypt.BCryptEncrypt(BCryptKeyH, BCryptInput, ULONG(len(BCryptInput) - 1), None, BCryptIV, ULONG(len(BCryptIV) - 1), BCryptOutput, ULONG(len(BCryptOutput)), byref(BCryptOuputS), ULONG(0))
  cipher_text = bytes(BCryptOutput[0:BCryptOuputS.value])
  bcrypt.BCryptDestroyKey(BCryptKeyH, ULONG(0))
  bcrypt.BCryptCloseAlgorithmProvider(BCryptProviderH, ULONG(0))
  return cipher_text

def SendtoMiXplorerTCP(ip, port, password, source, target):
  md5_password = hashlib.md5(password.encode('utf-8')).hexdigest().encode('utf-8')
  last_modified_time = os.path.getmtime(source)
  size = os.path.getsize(source)
  filename = '/' + target.lstrip('/')
  message = b'0\n' + md5_password + b'\n' + str(size).encode('utf-8') + b'\n' + str(int(last_modified_time)).encode('utf-8') + b'000\n' + filename.encode('utf-8')
  plain_message = message + b'\x00' * (15 - (len(message) + 15) % 16)
  iv = bytes(random.randint(0,255) for i in range(16))
  cipher_message = AESCipher(plain_message, md5_password, iv)
  sock = socket.socket()
  sock.connect((ip, port))
  sock.sendall(iv + cipher_message)
  sock.recv(100)
  file = open(source, 'rb')
  shutil.copyfileobj(file, sock.makefile('wb'))
  file.close()
  sock.close()