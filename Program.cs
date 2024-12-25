using System;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

public class SCCMSiteCodeHunter
{
    private static void FindManagementPointsAndSiteServer(string domain, string username = null, string password = null, bool useLdaps = false, bool debug = false)
    {
        int ldapPort = useLdaps ? 636 : 389;
        string protocol = useLdaps ? "ldaps://" : "ldap://";
        string searchBase = FqdnToBaseDn(domain);

        try
        {
            if (debug)
            {
                Console.WriteLine($"[DEBUG] LDAP Protocol: {protocol}");
                Console.WriteLine($"[DEBUG] LDAP Port: {ldapPort}");
                Console.WriteLine($"[DEBUG] Search Base: {searchBase}");
                Console.WriteLine($"[DEBUG] Using credentials: {(!string.IsNullOrEmpty(username) ? username : "Current User Context")}");
            }

            Console.WriteLine($"[+] Connecting to {protocol}{domain}:{ldapPort}...");

            var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(domain, ldapPort, useLdaps, false));

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                ldapConnection.Credential = new NetworkCredential(username, password, domain);
            }

            ldapConnection.AuthType = AuthType.Negotiate;

            string searchFilter = "(objectclass=mSSMSManagementPoint)";
            string[] searchAttributes = { "mSSMSMPName", "distinguishedName", "name", "mSSMSSiteCode" };

            if (debug)
            {
                Console.WriteLine($"[DEBUG] LDAP Search Filter: {searchFilter}");
                Console.WriteLine($"[DEBUG] LDAP Search Attributes: {string.Join(", ", searchAttributes)}");
            }

            var searchRequest = new SearchRequest(searchBase, searchFilter, SearchScope.Subtree, searchAttributes);

            var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

            if (debug)
            {
                Console.WriteLine($"[DEBUG] LDAP Search Response: {searchResponse.Entries.Count} entries found.");
            }

            string siteCode = null;
            string managementPoint = null;

            foreach (SearchResultEntry entry in searchResponse.Entries)
            {
                managementPoint = entry.Attributes["mSSMSMPName"]?[0]?.ToString() ?? "Unknown";
                Console.WriteLine($"[+] Found Management Point: {managementPoint}");

                if (debug)
                {
                    Console.WriteLine("[DEBUG] Entry Attributes:");
                    foreach (string attr in entry.Attributes.AttributeNames)
                    {
                        Console.WriteLine($"[DEBUG] {attr}: {entry.Attributes[attr][0]}");
                    }
                }

                siteCode = entry.Attributes["mSSMSSiteCode"]?[0]?.ToString() ?? "Unknown";
                Console.WriteLine($"    [+] Associated Site Code: {siteCode}");
            }

            if (!string.IsNullOrEmpty(siteCode))
            {
                FindSiteServer(ldapConnection, searchBase, siteCode, managementPoint, debug);
            }
            else
            {
                Console.WriteLine("[!] Could not determine the Site Code.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Error: {ex.Message}");
            if (debug)
            {
                Console.WriteLine($"[DEBUG] Stack Trace: {ex.StackTrace}");
            }
        }
    }

    private static void FindSiteServer(LdapConnection ldapConnection, string searchBase, string siteCode, string managementPoint, bool debug)
    {
        try
        {
            string searchFilter = $"(&(objectClass=*)(mSSMSSiteCode={siteCode}))";
            string[] searchAttributes = { "name", "distinguishedName", "mSSMSSiteCode", "mSSMSMPName", "dNSHostName", "mSSMSSiteServer" };

            if (debug)
            {
                Console.WriteLine($"[DEBUG] Searching for Site Server with Site Code: {siteCode}");
                Console.WriteLine($"[DEBUG] LDAP Search Filter: {searchFilter}");
            }

            var searchRequest = new SearchRequest(searchBase, searchFilter, SearchScope.Subtree, searchAttributes);
            var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

            bool validServerFound = false;

            if (searchResponse.Entries.Count > 0)
            {
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    string siteServer = entry.Attributes["name"]?[0]?.ToString() ?? "Unknown";
                    string dnsHostName = entry.Attributes["dNSHostName"]?[0]?.ToString() ?? "Unknown";
                    string isSiteServer = entry.Attributes["mSSMSSiteServer"]?[0]?.ToString() ?? "false";

                    if (debug)
                    {
                        Console.WriteLine("[DEBUG] Site Server Attributes:");
                        foreach (string attr in entry.Attributes.AttributeNames)
                        {
                            Console.WriteLine($"[DEBUG] {attr}: {entry.Attributes[attr][0]}");
                        }
                    }

                    if (isSiteServer.ToLower() == "true" && SiteServerExists(dnsHostName))
                    {
                        Console.WriteLine($"[+] Valid Site Server: {siteServer} ({dnsHostName})");
                        validServerFound = true;
                    }
                    else
                    {
                        Console.WriteLine($"[!] Invalid Site Server: {siteServer} ({dnsHostName})");
                    }
                }
            }

            if (!validServerFound && !string.IsNullOrEmpty(managementPoint))
            {
                Console.WriteLine($"[+] No valid Site Server found. Using Management Point as fallback: {managementPoint}");
            }
            else if (!validServerFound)
            {
                Console.WriteLine("[!] No valid Site Server or fallback Management Point found.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Error while searching for Site Server: {ex.Message}");
        }
    }

    private static bool SiteServerExists(string dnsHostName)
    {
        try
        {
            var hostEntry = System.Net.Dns.GetHostEntry(dnsHostName);
            return hostEntry != null;
        }
        catch
        {
            return false;
        }
    }

    private static string FqdnToBaseDn(string fqdn)
    {
        if (string.IsNullOrEmpty(fqdn))
        {
            throw new ArgumentNullException(nameof(fqdn), "FQDN cannot be null or empty.");
        }

        return string.Join(",", fqdn.Split('.').Select(part => $"DC={part}"));
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Usage: SiteCodeHunter.exe --domain <domain> [--username <username>] [--password <password>] [--ldaps] [--debug]");
        Console.WriteLine("Options:");
        Console.WriteLine("  --domain       Specify the domain name to query.");
        Console.WriteLine("  --username     Specify the username for authentication.");
        Console.WriteLine("  --password     Specify the password for authentication.");
        Console.WriteLine("  --ldaps        Use LDAPS (secure LDAP) for the query.");
        Console.WriteLine("  --debug        Enable debug output.");
        Console.WriteLine("  --help         Show this help message.");
    }

    public static void Main(string[] args)
    {
        var arguments = new Dictionary<string, string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("--"))
            {
                string key = args[i];
                string value = (i + 1 < args.Length && !args[i + 1].StartsWith("--")) ? args[++i] : null;
                arguments[key] = value;
            }
        }

        if (arguments.ContainsKey("--help"))
        {
            ShowHelp();
            return;
        }

        if (!arguments.ContainsKey("--domain") || string.IsNullOrEmpty(arguments["--domain"]))
        {
            Console.WriteLine("[!] Error: --domain is required.");
            ShowHelp();
            return;
        }

        string domain = arguments["--domain"];
        string username = arguments.ContainsKey("--username") ? arguments["--username"] : null;
        string password = arguments.ContainsKey("--password") ? arguments["--password"] : null;
        bool useLdaps = arguments.ContainsKey("--ldaps");
        bool debug = arguments.ContainsKey("--debug");

        if (debug)
        {
            Console.WriteLine($"[DEBUG] Domain: {domain}");
            Console.WriteLine($"[DEBUG] Username: {username ?? "null"}");
            Console.WriteLine($"[DEBUG] Use LDAPS: {useLdaps}");
        }

        try
        {
            FindManagementPointsAndSiteServer(domain, username, password, useLdaps, debug);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] An error occurred: {ex.Message}");
            if (debug)
            {
                Console.WriteLine($"[DEBUG] Stack Trace: {ex.StackTrace}");
            }
        }
    }
}
