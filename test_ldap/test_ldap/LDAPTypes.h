#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>

namespace LDAPUtils
{
    enum class OutputFormat
    {
        CSV,
        TXT,
        JSON,
        XML,
        HTML,
        CONSOLE_ONLY
    };

    enum class SearchMode
    {
        STANDARD,           // Normal LDAP search
        BY_DN,             // Search by specific DN
        BY_ATTRIBUTE       // Search by specific attribute value
    };

    struct Entry
    {
        std::wstring dn;
        std::map<std::wstring, std::vector<std::wstring>> attrs;
    };

    struct SearchConfig
    {
        std::wstring serverAddress = L"labrecon.com";
        std::wstring username = L"admin1";
        std::wstring password = L"admin1hihinopro";
        std::wstring baseDN = L"DC=labrecon,DC=com";
        std::wstring filter = L"(objectClass=*)";
        std::wstring attributesStr = L"*";
        std::wstring outputFile = L"";
        OutputFormat format = OutputFormat::CONSOLE_ONLY;
        //unsigned long scope = 2; // LDAP_SCOPE_SUBTREE
        unsigned long scope = 1;
        unsigned long sizeLimit = 10000;
        SearchMode searchMode = SearchMode::STANDARD;
        std::wstring searchDN = L"";
        std::wstring searchAttribute = L"";
        std::wstring searchValue = L"";
    };

    struct Statistics
    {
        int totalEntries = 0;
        int totalAttributes = 0;
        std::map<std::wstring, int> attributeCount;
        std::map<std::wstring, int> objectClassCount;
        std::map<std::wstring, std::set<std::wstring>> uniqueValues;
    };
}