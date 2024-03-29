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
The clock on the right side is a Dial the will tell the probablity of the file of being a virus
In the side bar there are 5 options:
- Home Screen
- Directory Analysis
- IP Analysis
- Terms and Services
- Configuration
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
Here, we will interface with virus total, and perform Fuzzy Hashing Analysis <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/a3bc969d-7525-4ef9-88d5-1ccb8ea0fa2e)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/dc792c27-8240-46f0-8ae8-f961ac11d2c7)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/ce9ec992-412f-4c33-959b-ea4f9a664da3)

## Directory Analysis
Sending each file from Directory to Virus Total: <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/9a2f3b65-2621-41e7-9fa4-333f8ed042e3)
## IP Analysis
Using PyDivert to block IP's found suspicious in DNS cache by Virus total: <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/64f31cb2-3a4c-4998-bcc1-8545ea1829f4)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/64855ec5-17a1-4203-a0c0-2fa83bdb48a4)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/9478b742-1254-4c0b-901e-2d2b10d3848d)
## Configuration
The user can configure 3 options:
- Virus Total Search
- Vaulting
- Data Base saving (Redis Data Base) <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/70c26a11-47ee-442f-96ee-c3a1239ad589)
## Quarnatine
If the file was found to have a probability of being malicious greater than 75 percent, it will go into quarantine.
The system will encrypt the file, and put it into a Hidden folder.<br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/83f4ce2f-0bed-4f59-885f-883fb3d2ff7c)
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/574689e7-a780-4fa2-be8a-03259051b078) <br><br>
To release from quarantine, go into the configuration and disable the vaulting: <br><br>
![image](https://github.com/eladyesh/Anti_Virus/assets/102996033/690a4001-560c-43f4-8514-392e96903b08)


## Full Project Book
This is the full project book (51 pages). Written in Hebrew: <br><br>
[elad2.docx](https://github.com/eladyesh/Anti_Virus/files/11649876/elad2.docx)

