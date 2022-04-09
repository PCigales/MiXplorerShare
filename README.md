# MiXplorerShare
A script in Python 3 to transfer files with MiXplorer Share

As of the version 6.57 of MiXplorer, the TCP server has been removed, and the "share" function has been switched to the FTP server, so the script MiXplorerTCP no longer works with versions released after 6.56.5. A new script, MiXplorerFTP has been created to cope with this change. It has been tested with the version 6.58.4.

New script MiXplorerFTP - only works with versions of MiXplorer from 6.58.4

This script provides a way to transfer files and folders between a computer under Windows and an Android phone running the application MiXplorer (http://mixplorer.com/ and https://play.google.com/store/apps/details?id=com.mixplorer.silver) through its FTP sharing functionality.
To work properly, it needs the chosen port to be authorized in the firewall on the computer for TCP incoming and outgoing connections.
The same port and the same user and password must be used in the script parameters and, for sending files to the phone, in the settings of the FTP server in MiXplorer, and for receiving files from the phone, in the settings of the "send to" panel in MiXplorer.
The script can operate in unencrypted mode (FTP) or explicit secured mode (FTPS), the latter requiring that the FTP server in MiXplorer to be configured with "TLS/SSL" enabled with "Explicit" option set. Because of the use of unauthenticated certificates, it may be necessary to declare the script as a trusted application in the antivirus settings related to network monitoring and encrypted connections scanning.

Help can be obtained with "mixplorerftp -h" or "mixplorerftp s -h" for sending and "mixplorerftp r -h" for receiving.

Examples (supposing the FTP server is set up with "port" set to "9000", "user" set to "me" and "password" set to "test":

- mixplorerftp s -i 192.168.1.10 -p 9000 -u me -w test "C:\Users\XXX\Downloads\test1" "C:\Users\XXX\Downloads\test2.txt" -r copytest : will send the "test1" folder and its content and the file "test2.txt" to a subfolder "copytest" existing on the working folder on the phone whose ip is "192.168.1.10"
- mixplorerftp s -i MyPhone -p 9000 -u me -w test "C:\Users\XXX\Downloads\test\." : will send the content of the "test" folder to the working folder on the phone whose DNS registered host name is "Myphone" (probably needs to be manually recorded on the DNS server)
- mixplorerftp s -p 9000 -u me -w test "C:\Users\XXX\Downloads\test.txt" -s -v : will copy the file "test.txt" in the working folder of the first phone found during scanning in explicit secured mode, verbosely displaying the process
- mixplorerftp r -p 9000 -u me -w test -d PCW10 -r "C:\Users\me\Downloads\phone" : will be detected as PCW10 used by me, and store files and folders received in the folder "phone"
- mixplorerftp r -p 9000 -u me -w test -r "C:\Users\XXX\Downloads\phone" -s -k pass : will be detected as PCW10 used by me, and store files and folders received in the folder "phone", using secure connection (if requested by MiXplorer, which should be the case), decrypting the private key "key.pem" (see below) with the password "pass"

Files and folders are not overwritten, they are renamed if already present.

Tips:
 - for secure communications (must also be set in MiXplorer FTP server), a certificate and its associated private key can be provided, by storing them as "cert.pem" and "key.pem" in the same folder than the script (otherwise, the script will generate and use an ephemeral self signed certificate); both files can be obtained by running "openssl req -x509 -newkey -keyout key.pem -out cert.pem -days 3650" (the password entered when requested must be provided to the script through the "-k" argument, or to do without password, "-nodes" must be added to the command line)
 - to make files transfer easier:
   - create a shortcut in "%AppData%\Microsoft\Windows\SendTo" to "C:\Windows\py.exe "[path to the script]" s -p [port] -u [user] -w [password] -i [ip or DNS name of the phone]" (a phone icon can be found in "%SystemRoot%\System32\imageres.dll")
   - in the registry, create the keys and entries below (to add the receive command to the "shift + right click" context menu):  
     . HKEY_CLASSES_ROOT\Directory\shell\MiXplorerFTP:  
       "@": "Receive from [name of the phone] (FTP)"  
       "Extended": ""  
       "Icon": "%windir%\system32\imageres.dll,42"  
       "Position": "bottom"  
     . HKEY_CLASSES_ROOT\Directory\shell\MiXplorerFTP\command:  
       "@": "C:\Windows\py.exe "[path to the script]" r -p [port] -d [device] -u [user] -w [password] -r "%v""  
     . HKEY_CLASSES_ROOT\Directory\Background\shell\MiXplorerFTP  
       "@": "Receive from [name of the phone] (FTP)"  
       "Extended": ""  
       "Icon": "%windir%\system32\imageres.dll,42"  
       "Position": "bottom"  
     . HKEY_CLASSES_ROOT\Directory\Background\shell\MiXplorerFTP\command  
       "@": "C:\Windows\py.exe "[path to the script]" r -p [port] -d [device] -u [user] -w [password] -r "%v""  

------------------------------------------------------------

Old script MiXplorerTCP - only works with versions of MiXplorer up to 6.56.5

This script provides a way to transfer files and folders between a computer under Windows and an Android phone running the application MiXplorer (http://mixplorer.com/ and https://play.google.com/store/apps/details?id=com.mixplorer.silver) through its TCP sharing functionality.
To work properly, it needs the chosen port to be authorized in the firewall on the computer for TCP incoming and outgoing connections. The same port and the same password must be used in the script and in the settings of the TCP server in MiXplorer.

Help can be obtained with "mixplorertcp -h" or "mixplorertcp s -h" for sending and "mixplorertcp r -h" for receiving.

Examples (supposing the TCP server is set up with "port" set to "9000" and "password" set to "test":

- mixplorertcp s -i 192.168.1.10 -p 9000 -w test "C:\Users\XXX\Downloads\test1" "C:\Users\XXX\Downloads\test2.txt" -d copytest : will send the "test1" folder and its content and the file "test2.txt" to a subfolder "copytest" created on the current folder on the phone whose ip is "192.168.1.10"
- mixplorertcp s -i MyPhone -p 9000 -w test "C:\Users\XXX\Downloads\test\." : will send the content of the "test" folder to the current folder on the phone whose DNS registered host name is "Myphone" (probably needs to be manually recorded on the DNS server)
- mixplorertcp s -p 9000 -w test "C:\Users\XXX\Downloads\test.txt" -d "/storage/emulated/0/Download/copied.txt" : will copy the file "test.txt" to a file called "copied.txt" in the "Download" folder of the emulated SD Card on the first phone found during scanning
- mixplorertcp r -p 9000 -w test -u XXX -d PC_XXX -r "C:\Users\XXX\Downloads\phone" : will be detected as PC_XXX used by XXX, and store files and folders received in the folder "phone", creating it and subfolders if not existing
- mixplorertcp r -p 9000 -w test -u XXX -r "C:\Users\XXX\Downloads\phone" -s -k pass : will be detected as PC used by XXX, and store files and folders received in the folder "phone", creating it and subfolders if not existing, and uses secure communications, decrypting the private key "key.pem" (see below) with the password "pass"

Files are not overwritten, they are renamed if already present.

Tips:
 - for secure communications (must also be set in MiXplorer TCP server), a certificate and its associated private key can be provided, by storing them as "cert.pem" and "key.pem" in the same folder than the script (otherwise, the script will generate and use an ephemeral self signed certificate); both files can be obtained by running "openssl req -x509 -newkey -keyout key.pem -out cert.pem -days 3650" (the password entered when requested must be provided to the script through the "-k" argument, or to do without password, "-nodes" must be added to the command line)
 - to make files transfer easier:
   - create a shortcut in "%AppData%\Microsoft\Windows\SendTo" to "C:\Windows\py.exe "[path to the script]" s -p [port] -w [password] -i [ip or DNS name of the phone]" (a phone icon can be found in "%SystemRoot%\System32\imageres.dll")
   - in the registry, create the keys and entries below (to add the receive command to the "shift + right click" context menu):  
     . HKEY_CLASSES_ROOT\Directory\shell\MiXplorerTCP:  
       "@": "Receive from [name of the phone] (TCP)"  
       "Extended": ""  
       "Icon": "%windir%\system32\imageres.dll,42"  
       "Position": "bottom"  
     . HKEY_CLASSES_ROOT\Directory\shell\MiXplorerTCP\command:  
       "@": "C:\Windows\py.exe "[path to the script]" r -p [port] -u [user] -d [device] -w [password] -r "%v""  
     . HKEY_CLASSES_ROOT\Directory\Background\shell\MiXplorerTCP  
       "@": "Receive from [name of the phone] (TCP)"  
       "Extended": ""  
       "Icon": "%windir%\system32\imageres.dll,42"  
       "Position": "bottom"  
     . HKEY_CLASSES_ROOT\Directory\Background\shell\MiXplorerTCP\command  
       "@": "C:\Windows\py.exe "[path to the script]" r -p [port] -u [user] -d [device] -w [password] -r "%v""  
