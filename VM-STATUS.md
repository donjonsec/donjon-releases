# SSH Debug Round 2

## File permissions on administrators_authorized_keys
C:\ProgramData\ssh\administrators_authorized_keys BUILTIN\Administrators:(F)
                                                  NT AUTHORITY\SYSTEM:(F)

Successfully processed 1 files; Failed processing 0 files


## OpenSSH event log


TimeCreated : 3/21/2026 11:00:21 PM
Message     : sshd: Connection closed by authenticating user administrator 192.168.1.101 port 43653 [preauth]

TimeCreated : 3/21/2026 11:00:21 PM
Message     : sshd: Failed password for administrator from 192.168.1.101 port 43653 ssh2

TimeCreated : 3/21/2026 11:00:21 PM
Message     : sshd: Failed password for administrator from 192.168.1.101 port 43653 ssh2

TimeCreated : 3/21/2026 10:59:41 PM
Message     : sshd: Server listening on 0.0.0.0 port 22.

TimeCreated : 3/21/2026 10:59:41 PM
Message     : sshd: Server listening on :: port 22.

TimeCreated : 3/21/2026 10:58:10 PM
Message     : sshd: Connection closed by authenticating user administrator 192.168.1.101 port 45418 [preauth]

TimeCreated : 3/21/2026 10:53:30 PM
Message     : sshd: Connection closed by authenticating user administrator 192.168.1.101 port 6347 [preauth]

TimeCreated : 3/21/2026 10:53:30 PM
Message     : sshd: Failed password for administrator from 192.168.1.101 port 6347 ssh2

TimeCreated : 3/21/2026 10:53:30 PM
Message     : sshd: Failed password for administrator from 192.168.1.101 port 6347 ssh2

TimeCreated : 3/21/2026 10:53:07 PM
Message     : sshd: Connection closed by authenticating user DONJONSEC\\\\administrator 192.168.1.101 port 10966 
              [preauth]





## sshd_config full dump
Port 22
PasswordAuthentication yes
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe


## administrators_authorized_keys content
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY


## File encoding check

## File encoding check


           Path: C:\ProgramData\ssh\administrators_authorized_keys

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   73 73 68 2D 65 64 32 35 35 31 39 20 41 41 41 41  ssh-ed25519 AAAA
00000010   43 33 4E 7A 61 43 31 6C 5A 44 49 31 4E 54 45 35  C3NzaC1lZDI1NTE5
00000020   41 41 41 41 49 4F 38 54 6B 38 33 6F 35 53 50 71  AAAAIO8Tk83o5SPq
00000030   77 58 6C 6D 31 34 38 5A 73 55 6F 52 58 6A 66 34  wXlm148ZsUoRXjf4
00000040   43 51 4F 4A 2B 31 64 78 67 6A 6E 52 6A 79 58 59  CQOJ+1dxgjnRjyXY
00000050   0D 0A                                            ..              



