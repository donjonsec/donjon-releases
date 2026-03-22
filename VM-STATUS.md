# SSH Fix Results ΓÇö 2026-03-21 23:38:28

## sshd service account
Runs as: LocalSystem
State: Running

## sshd_config
Port 22
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
LogLevel DEBUG
Subsystem sftp sftp-server.exe


## Security Event 4625 (logon failures)
  User=Administrator LogonType=7 SubStatus=0xc000006a
  User=Administrator LogonType=3 SubStatus=0xc000006a
  User=Administrator LogonType=3 SubStatus=0xc000006a

## GPO Network Logon Rights

C:\donjon-agent\secpol2.cfg:97:SeNetworkLogonRight = *S-1-1-0,*S-1-5-11,*S-1-5-32-544,*S-1-5-32-554,*S-1-5-9




## SSH Self-Test (password via paramiko)
SSH OK: donjonsec\administrator
