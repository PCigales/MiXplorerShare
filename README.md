# MiXplorerTCP
A script in Python 3 to send a file to a MiXplorer TCP server

This script provides a way to transfer files and folders between a computer under Windows and an Android phone running the application MiXplorer (http://mixplorer.com/ and https://play.google.com/store/apps/details?id=com.mixplorer.silver) through its TCP sharing functionality.
To work properly, it needs the chosen port to be authorized in the firewall on the computer for TCP incoming and outgoing connections. The same port and the same password must be used in the script and in the settings of the TCP server in MiXplorer.

Help can be obtained with "mixplorertcp -h" or "mixplorertcp s -h" for sending and "mixplorertcp r -h" for receiving.

Examples (supposing the TCP server is set up with "port" set to "9000" and "password" set to "test":

- mixplorertcp s -i 192.168.1.10 -p 9000 -w test "C:\Users\XXX\Downloads\test" -d copytest : will send the "test" folder and its content to a subfolder "copytest" created on the current folder on the phone
- mixplorertcp s -i 192.168.1.10 -p 9000 -w test "C:\Users\XXX\Downloads\test\." : will send the content of the "test" folder to the current folder on the phone
- mixplorertcp s -p 9000 -w test "C:\Users\XXX\Downloads\test.txt" -d "/storage/emulated/0/Download/copied.txt" : will copy the file "test.txt" to a file called "copied.txt" in the "Download" folder of the emulated SD Card on the first phone found during scanning
- mixplorertcp r -p 9000 -w test -u XXX -d PC_XXX -r "C:\Users\XXX\Downloads\phone" : will be detected as PC_XXX used by XXX, and store files and folders received in the folder "phone", creating it and subfolders if not existing

Files are not overwritten, they are renamed if already present.
