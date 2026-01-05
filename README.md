
# Unity CVE-2025-59489 PoC malware loader
 
### Features
 - Uses an older standalone game made in unity to abuse debugging flags to load a malicious library into the game's process space
 - Utilizes PEB memory walking to find already loaded libraries like ntdll and kernel32
 - Registers a new service as a means of privilege escalation to system








# DISCLAIMER:
## This repository is for educational purposes only, and the creator does not take any responsibility for incidents that occur due to the usage of this repository
## The software is provided as is.


