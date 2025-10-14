#include "LDAPTypes.h"
#include "LDAPConnection.h"
#include "LDAPConverters.h"
#include "LDAPStatistics.h"
#include <iostream>
#include <fcntl.h>
#include <io.h>

using namespace LDAPUtils;

void PrintUsage()
{
    std::wcout << LR"(
╔═══════════════════════════════════════════════════════════════════════════╗
║              LDAP Advanced Query Tool - Multi-Format Export              ║
╚═══════════════════════════════════════════════════════════════════════════╝

USAGE:
    ldap_tool.exe [options]

CONNECTION OPTIONS:
    -s, --server <address>      LDAP server address (default: labrecon.com)
    -u, --username <name>       Username for authentication (default: admin1)
    -p, --password <pass>       Password for authentication
    -b, --basedn <dn>          Base DN for search (default: DC=labrecon,DC=com)

SEARCH OPTIONS:
    -f, --filter <filter>      LDAP filter (default: (objectClass=*))
    -a, --attributes <attrs>   Comma-separated attributes or * for all (default: *)
    --scope <scope>            Search scope: base, one, sub (default: sub)
    --limit <number>           Size limit (default: 10000)

ADVANCED SEARCH:
    --search-dn <dn>           Search specific DN only
    --search-attr <attr>       Search by attribute name
    --search-value <value>     Search by attribute value (use with --search-attr)

OUTPUT OPTIONS:
    -o, --output <file>        Output file path
    -t, --type <format>        Output format: csv, txt, json, xml, html, console
                               (default: console)

OUTPUT FORMATS:
    csv      - CSV with UTF-8 BOM (Excel-compatible)
    txt      - Formatted text file
    json     - JSON format
    xml      - XML format
    html     - Interactive HTML with statistics and filtering
    console  - Console output only (no file export)

STATISTICS:
    --stats                    Show detailed statistics after search

EXAMPLES:
    # Export all entries to interactive HTML
    ldap_tool.exe -o results.html -t html

    # Search by specific DN
    ldap_tool.exe --search-dn "CN=admin1,CN=Users,DC=labrecon,DC=com"

    # Search by attribute
    ldap_tool.exe --search-attr "sAMAccountName" --search-value "admin1" -o user.json -t json

    # Search users only and export to CSV
    ldap_tool.exe -f "(objectClass=user)\" -a "cn,mail,department" -o users.csv -t csv

        # Search with statistics
        ldap_tool.exe -f "(objectClass=*)\" --stats -t console

        # Custom server with all attributes to HTML
        ldap_tool.exe -s "mydc.company.com" -u "admin" -p "pass123" -o all.html -t html

        )" << std::endl;
}

int main(int argc, char* argv[])
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    SearchConfig config;
    bool showStats = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            PrintUsage();
            return 0;
        }
        else if ((arg == "-s" || arg == "--server") && i + 1 < argc)
        {
            config.serverAddress = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-u" || arg == "--username") && i + 1 < argc)
        {
            config.username = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < argc)
        {
            config.password = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-b" || arg == "--basedn") && i + 1 < argc)
        {
            config.baseDN = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-f" || arg == "--filter") && i + 1 < argc)
        {
            config.filter = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-a" || arg == "--attributes") && i + 1 < argc)
        {
            config.attributesStr = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc)
        {
            config.outputFile = Converters::StringToWString(argv[++i]);
        }
        else if ((arg == "-t" || arg == "--type") && i + 1 < argc)
        {
            std::string typeStr = argv[++i];
            if (typeStr == "csv") config.format = OutputFormat::CSV;
            else if (typeStr == "txt") config.format = OutputFormat::TXT;
            else if (typeStr == "json") config.format = OutputFormat::JSON;
            else if (typeStr == "xml") config.format = OutputFormat::XML;
            else if (typeStr == "html") config.format = OutputFormat::HTML;
            else if (typeStr == "console") config.format = OutputFormat::CONSOLE_ONLY;
            else
            {
                std::wcerr << L"Unknown format: " << Converters::StringToWString(typeStr) << std::endl;
                return 1;
            }
        }
        else if (arg == "--scope" && i + 1 < argc)
        {
            std::string scopeStr = argv[++i];
            if (scopeStr == "base") config.scope = 0;
            else if (scopeStr == "one") config.scope = 1;
            else if (scopeStr == "sub") config.scope = 2;
        }
        else if (arg == "--limit" && i + 1 < argc)
        {
            config.sizeLimit = std::stoi(argv[++i]);
        }
        else if (arg == "--search-dn" && i + 1 < argc)
        {
            config.searchMode = SearchMode::BY_DN;
            config.searchDN = Converters::StringToWString(argv[++i]);
        }
        else if (arg == "--search-attr" && i + 1 < argc)
        {
            config.searchMode = SearchMode::BY_ATTRIBUTE;
            config.searchAttribute = Converters::StringToWString(argv[++i]);
        }
        else if (arg == "--search-value" && i + 1 < argc)
        {
            config.searchValue = Converters::StringToWString(argv[++i]);
        }
        else if (arg == "--stats")
        {
            showStats = true;
        }
    }

    // Auto-generate output filename
    if (config.format != OutputFormat::CONSOLE_ONLY && config.outputFile.empty())
    {
        switch (config.format)
        {
        case OutputFormat::CSV: config.outputFile = L"ldap_results.csv"; break;
        case OutputFormat::TXT: config.outputFile = L"ldap_results.txt"; break;
        case OutputFormat::JSON: config.outputFile = L"ldap_results.json"; break;
        case OutputFormat::XML: config.outputFile = L"ldap_results.xml"; break;
        case OutputFormat::HTML: config.outputFile = L"ldap_results.html"; break;
        default: break;
        }
    }

    std::wcout << L"╔═══════════════════════════════════════════════════════════════╗" << std::endl;
    std::wcout << L"║        LDAP Advanced Query Tool - Multi-Format Export        ║" << std::endl;
    std::wcout << L"╚═══════════════════════════════════════════════════════════════╝" << std::endl;
    std::wcout << L"\n⚙️  Configuration:" << std::endl;
    std::wcout << L"  Server: " << config.serverAddress << std::endl;
    std::wcout << L"  Base DN: " << config.baseDN << std::endl;

    if (config.searchMode == SearchMode::BY_DN)
    {
        std::wcout << L"  Mode: Search by DN" << std::endl;
        std::wcout << L"  Target DN: " << config.searchDN << std::endl;
    }
    else if (config.searchMode == SearchMode::BY_ATTRIBUTE)
    {
        std::wcout << L"  Mode: Search by Attribute" << std::endl;
        std::wcout << L"  Attribute: " << config.searchAttribute << L" = " << config.searchValue << std::endl;
    }
    else
    {
        std::wcout << L"  Filter: " << config.filter << std::endl;
        std::wcout << L"  Attributes: " << (config.attributesStr == L"*" ? L"All (*)" : config.attributesStr) << std::endl;
    }

    if (config.format != OutputFormat::CONSOLE_ONLY)
    {
        std::wcout << L"  Output: " << config.outputFile << std::endl;
    }
    std::wcout << std::endl;

    LDAPConnection ldap(config.serverAddress);

    if (ldap.Connect(config.username, config.password, config.serverAddress))
    {
        std::wcout << L"✓ Successfully connected to LDAP server." << std::endl << std::endl;

        std::vector<Entry> entries;
        Statistics stats;

        if (config.searchMode == SearchMode::BY_DN)
        {
            Entry entry;
            if (ldap.SearchByDN(config.searchDN, entry))
            {
                std::wcout << L"\n✓ Found entry for DN: " << config.searchDN << std::endl;
                std::wcout << L"\nAttributes:" << std::endl;
                for (const auto& attr : entry.attrs)
                {
                    std::wcout << L"  " << attr.first << L": ";
                    for (size_t i = 0; i < attr.second.size(); ++i)
                    {
                        if (i > 0) std::wcout << L"; ";
                        std::wcout << attr.second[i];
                    }
                    std::wcout << std::endl;
                }
                entries.push_back(entry);
            }
            else
            {
                std::wcerr << L"✗ DN not found or error occurred." << std::endl;
            }
        }
        else if (config.searchMode == SearchMode::BY_ATTRIBUTE)
        {
            ldap.SearchByAttribute(config.searchAttribute, config.searchValue, config, entries);
        }
        else
        {
            ldap.Search(config, entries, stats);
        }

        if (showStats && !entries.empty())
        {
            stats = StatisticsCalculator::Calculate(entries);
            StatisticsCalculator::PrintStatistics(stats);
        }
    }
    else
    {
        std::wcerr << L"✗ Failed to connect to LDAP server." << std::endl;
        return 1;
    }

    std::wcout << L"\n✓ Done! Press any key to exit..." << std::endl;
    std::wcin.get();
    return 0;
}