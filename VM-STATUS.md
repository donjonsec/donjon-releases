# VM Status ΓÇö SSH Debug + Screen Lock ΓÇö 2026-03-21 23:33:45

## Screen Lock
Disabled: Yes

## SSH Debug
Port 22: True
sshd: Running

## sshd_config
Port 22
PasswordAuthentication yes
PubkeyAuthentication no
Subsystem sftp sftp-server.exe


## Admin Account
Locked: False
Enabled: True
Password Expired: False

## Firewall

DisplayName               Enabled Direction Action
-----------               ------- --------- ------
OpenSSH SSH Server (sshd)    True   Inbound  Allow




## Logon Rights

C:\donjon-agent\secpol.cfg:97:SeNetworkLogonRight = *S-1-1-0,*S-1-5-11,*S-1-5-32-544,*S-1-5-32-554,*S-1-5-9




## SSH Self-Test
Result: ** WARNING: connection is not using a post-quantum key exchange algorithm. ** This session may be vulnerable to "store now, decrypt later" attacks. ** The server may need to be upgraded. See https://openssh.com/pq.html administrator@localhost: Permission denied (password,keyboard-interactive).

## NOTE
BatchMode=yes cannot send passwords. SSH password auth IS working ΓÇö tested with paramiko earlier.
Password: Donj0n2026!
