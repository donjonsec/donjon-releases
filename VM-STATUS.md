# VM Status Report

## sshd_config contents
```
Port 22
PasswordAuthentication yes
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe
```

## sshd service status


Status    : Running
StartType : Automatic





## Port 22 listening

  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING
  TCP    [::]:22                [::]:0                 LISTENING




## authorized_keys files
### ProgramData
FILE NOT FOUND
### User .ssh
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY

## AD Status


DNSRoot     : test.donjonsec.local
NetBIOSName : DONJONSEC





## AD Users

Name          SamAccountName
----          --------------
Administrator Administrator 
Guest         Guest         
krbtgt        krbtgt        
Test User 1   testuser1     
Test User 2   testuser2     




## Python
Python 3.12.8

## IP

   IPv4 Address. . . . . . . . . . . : 192.168.1.200



