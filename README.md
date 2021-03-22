# MiXplorerTCP
A script in Python 3 to transfer files with MiXplorer TCP

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
 - to make files transfer easier, create a shortcut in "%AppData%\Microsoft\Windows\SendTo" to "C:\Windows\py.exe "[path to the script]" s -p [port] -w [password] -i [ip or DNS name of the phone]" (a phone icon can be found in "%SystemRoot%\System32\imageres.dll")
