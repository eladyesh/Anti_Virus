# Anti_Virus
An Anti-Virus project as part of Cyber-YB class.
Written in
- [x] C++
- [x] Python
- [x] YARA
- [x] C#
- [x] C

The project analyses and finds suspicious behaviour of various exe files.
## Main window
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/9465a011-5008-4344-bb99-63d5f83f4bab) 
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/242b11aa-9eeb-48a1-9609-86e5f62d08b6)<br><br>
Here, you can start the VM for the Dynamic Analysis, move the Static And Hash Analyis Windows.
In the side bar there are 5 options:
- Home Screen
- Directory Analysis
- IP Analysis
- Terms and Services
- Configuration
The clock on the right side is a Dial the will tell the probablity of the file of being a virus <br>
## Dynamic Analysis
VM when turned on:<br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/0d255f54-c437-4003-b998-621e2ec2d1fa)<br><br>
The batch file turns on the reciever that is waiting for the file. When the file is in the vm,
it injects the dll with the hooks, and then runs SysInternals Handle.exe. The results:<br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/4a103416-b640-4e2a-8889-79f21c8c5968)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/e49833d2-8622-49e7-a33d-8b87655413c6)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/661b639b-3c60-4d77-a66e-789850ec92fa)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/610445de-854a-4e6a-b961-0bef2a971dbd)

## Static Analysis
A few checks run on the file:
- Portable Executable info
- Suspicious Strings (YARA)
- Additional Strings (Sysinternals)
- Packers check (YARA)
- Imports - Done by going into the Import Address table of the IAT
- 3 PE checks - Fractionated Imports, Suspicious sections, and PE Linker test <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/e96256fb-438e-46f0-8bcb-30b533cc7436)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/3c23fd2b-12d3-48d6-8b59-0316509bb1f5)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/dd01cea0-a50b-48a3-a385-47e0f19f099c)



## Hash Analysis
Here, we will interface with virus total, and perform Fuzzy Hashing Analysis
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/a3bc969d-7525-4ef9-88d5-1ccb8ea0fa2e)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/dc792c27-8240-46f0-8ae8-f961ac11d2c7)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/ce9ec992-412f-4c33-959b-ea4f9a664da3)

## Directory Analysis
## IP Analysis
### I will complete this README when I finish the project
