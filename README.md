###### WARNING: THIS TROJAN IS A DISCORD RAT. IT IS NOT A GUI RAT.
###### This is a simple DiscordRAT programmed in Python to test my skills as a Developer. This is for educational purposes and is not supposed to be used as a legitimate malware for windows computers
###### Below are the Commands and Update Log.
###### For more information please go to my [Info Page](https://airstrike.school/Socrates)
###### To make a .exe build please visit the [Documentation Wiki](https://github.com/GiveUsername/ShittyTrojan.py/wiki)
###### If you want to see what I'm planning on adding next, got to the [ShittyTrojan Trello](https://trello.com/b/ck9dFLnF/shittytrojan)
###### Currently FUD on Malwarebytes, SentinelOne, McAffee.
###### Detected on known AV's: Kaspersky, Avast, AVG, Microsoft, Sophos.
###### [View VirusTotal Report](https://www.virustotal.com/gui/file/bf3306f6dcfa56a2f5f737b22a2ce82b5074f636762b19ab39dce171fde581f7/detection) (13/64 AntiVirus Flags) (TESTED ON OLDER VERSION, NEW TEST SOON)

# Commands

##### PROCESS:
###### !procs - Lists all running processes
###### !procsearch - Searches for a given process / Syntax: !procsearch notepad.exe
###### !prockill - Kills a given process / Syntax: !prockill notepad.exe
###### !procstart - Starts a process on the computer / Syntax: !procstart notepad.exe
###### !startup - Sets the .exe to startup (.exe file will run when pc boots)

##### DIRECTORY:
###### !cd - Changed the directory / Syntax: !cd C:\
###### !dir - Display all items in a directory
###### !download - Downloads a file from the target computer / Syntax !download textfile.txt
###### !upload - Uploads a file attachment to the target computer / Syntax: !upload [Attachment]
###### !filesearch - Searches for a a given file in the computer / Syntax: !filesearch notepad.exe (Will also give file location)

##### EXECUTION: 
###### !cmd - Executes a Cmd Prompt command on the computer / Syntax: !cmd systeminfo
###### !shell - Executes a PowerShell command on the computer / Syntax: !shell whoami

##### INFORMATION:
###### !info - Grabs information on the computer
###### !geolocate - Attempts to find the geo-location of the computer (Sort of broken if VPN is active)
###### !token - Grabs all available tokens on the target device
###### !passwords - Grabs all available passwords on the target device
###### !history - Grabs default browser history
###### !admincheck - Checks if the executable file has Administrator Permissions
###### !vpn - Searches for vpns within the computer (Application & Browser Extention)

##### MESSAGING:
###### !message - Opens a message screen containing the given message / Syntax: !message Hello
###### !audio - Uses Text-To-Speech to say a given phrase / Syntax: !audio Hello

##### SCREEN:
###### !webcams - Grabs all available webcams on the target device
###### !selectcam - Selects a given webcam / Syntax: !selectcam Webcam 0
###### !getcam - Takes a cam picture using selected webcam
###### !screenshot - Takes a screenshot of the main computer screen (Secondary not available)

##### OTHER:
###### !website - Opens a website using the default computer browser / Syntax: !website roblox.com
###### !wallpaper - Sets the computers wall paper to a given image / Syntax: !wallpaper [UploadedImage]
###### !admincheck - Checks if you have admin permissions on the target computer

# Update Log

### 4/27/24:
##### Commands:
###### !startup - Sets the .exe to startup (.exe file will run when pc boots)
###### !uacbypass - Elevates the .exe to Admin (Still under-development, most of the time will not work properly)
###### !filesearch - Searches for a a given file in the computer / Syntax: !filesearch notepad.exe (Will also give file location)
###### !vpn - Searches for vpns within the computer (Application & Browser Extention)
#### Command Updates:
###### !info - Optimized speed for VPN & VM Detetcion; Can now properly detect both
#### Things to work on:
###### !wallpaper - Needs to work on Win 11
###### !uacbypass - Must have a higher chance of elevation (Currently at about 8% per use)
###### Trojan Detection - Make .exe file FUD (Fully Undetected/Undetectable)

###  3/30/24
##### Commands:
###### !token - Grabs all available tokens on the target device
###### !passwords - Grabs all available passwords on the target device
###### !history - Grabs default browser history
###### !webcams - Grabs all available webcams on the target device
###### !selectcam - Selects a given webcam / Syntax: !selectcam Webcam 0
###### !getcam - Takes a cam picture using selected webcam
#### Command Updates:
###### Optimized most commands that detect Vpn's and VM's
###### Removed !uacbypass (Too Buggy + Barely Worked Functionaly)

