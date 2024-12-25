# SCCMSiteCodeHunter
While porting CMloot to CSharp I started writing a function to enumerate SCCM servers and thus this little utility was born. SiteCodeHunter or SCCMSiteCodeHunter will take a domain and/or credentials and connect to it over LDAP/LDAPS depending on what flags you give it, it'll then perform LDAP queries to get the sitecode and perform a bit of validation to identify if it is a valid sitecode or not.

It is primarily a utility for querying SCCM (System Center Configuration Manager) management points and site servers using LDAP. This program supports LDAPS for secure queries and includes debugging options for troubleshooting.

## Usage
```
SiteCodeHunter.exe --domain <domain> [--username <username>] [--password <password>] [--ldaps] [--debug]
```

- `--domain <domain>`: Specify the domain name to query (required)
- `--username <username>`: Specify the username for authentication (optional)
- `--password <password>`: Specify the password for authentication (optional)
- `--ldaps`: Use LDAPS (secure LDAP) for the query (optional)
- `--debug`: Enable debug output for troubleshooting (optional)
- `--help`: Show the help message

## Example Usage
Querying with default user context
```
SiteCodeHunter.exe --domain polaris.internal
[+] Connecting to ldap://polaris.internal:389...
[+] Found Management Point: SCCM-MGMT.POLARIS.INTERNAL
    [+] Associated Site Code: 123
[!] Invalid Site Server: SMS-Site-123 (Unknown)
[!] Invalid Site Server: SMS-MP-123-SCCM-MGMT.POLARIS.INTERNAL (sccm-mgmt.polaris.internal)
[+] No valid Site Server found. Using Management Point as fallback: SCCM-MGMT.POLARIS.INTERNAL
```

Querying with username and password
```
SiteCodeHunter.exe --domain polaris.internal --username user --password password
[+] Connecting to ldap://polaris.internal:389...
[+] Found Management Point: SCCM-MGMT.POLARIS.INTERNAL
    [+] Associated Site Code: 123
[!] Invalid Site Server: SMS-Site-123 (Unknown)
[!] Invalid Site Server: SMS-MP-123-SCCM-MGMT.POLARIS.INTERNAL (sccm-mgmt.polaris.internal)
[+] No valid Site Server found. Using Management Point as fallback: SCCM-MGMT.POLARIS.INTERNAL
```

Querying using LDAPS with debug enabled
```
SiteCodeHunter.exe --domain polaris.internal --ldaps --debug
[DEBUG] Domain: polaris.internal
[DEBUG] Username: null
[DEBUG] Use LDAPS: True
[DEBUG] LDAP Protocol: ldaps://
[DEBUG] LDAP Port: 636
[DEBUG] Search Base: DC=polaris,DC=internal
[DEBUG] Using credentials: Current User Context
[+] Connecting to ldaps://polaris.internal:636...
[DEBUG] LDAP Search Filter: (objectclass=mSSMSManagementPoint)
[DEBUG] LDAP Search Attributes: mSSMSMPName, distinguishedName, name, mSSMSSiteCode
[!] Error: The LDAP server is unavailable.
```