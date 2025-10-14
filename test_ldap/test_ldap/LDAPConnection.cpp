#include "LDAPConnection.h"
#include "LDAPConverters.h"
#include "LDAPStatistics.h"
#include "LDAPExporter.h"
#include <iostream>
#include <winber.h>

namespace LDAPUtils
{
    LDAPConnection::LDAPConnection(const std::wstring& serverAddress, unsigned long port)
        : ldapConnection(ldap_initW(const_cast<wchar_t*>(serverAddress.c_str()), port))
    {
        if (ldapConnection == NULL)
        {
            std::cerr << "LDAP initialization failed. Error: " << LdapGetLastError() << std::endl;
        }
    }

    LDAPConnection::~LDAPConnection()
    {
        Disconnect();
    }

    bool LDAPConnection::Connect(const std::wstring& username, const std::wstring& password, const std::wstring& domain)
    {
        if (ldapConnection == NULL)
            return false;

        unsigned long version = 3; // LDAP_VERSION3
        unsigned long returnCode = ldap_set_option(ldapConnection, 0x0011 /*LDAP_OPT_PROTOCOL_VERSION*/, (void*)&version);
        if (returnCode != 0)
        {
            std::cerr << "Failed to set LDAP protocol version" << std::endl;
            return false;
        }

        SEC_WINNT_AUTH_IDENTITY_W authIdent = {};
        authIdent.User = (unsigned short*)username.c_str();
        authIdent.UserLength = static_cast<unsigned long>(username.length());
        authIdent.Password = (unsigned short*)password.c_str();
        authIdent.PasswordLength = static_cast<unsigned long>(password.length());
        authIdent.Domain = (unsigned short*)domain.c_str();
        authIdent.DomainLength = static_cast<unsigned long>(domain.length());
        authIdent.Flags = 2; // SEC_WINNT_AUTH_IDENTITY_UNICODE

        returnCode = ldap_bind_sW(ldapConnection, NULL, (wchar_t*)&authIdent, 0x0486 /*LDAP_AUTH_NEGOTIATE*/);
        if (returnCode != 0)
        {
            std::cerr << "LDAP bind failed. Error: " << returnCode << std::endl;
            return false;
        }
        return true;
    }

    void LDAPConnection::Disconnect()
    {
        if (ldapConnection != NULL)
        {
            ldap_unbind(ldapConnection);
            ldapConnection = NULL;
        }
    }

    bool LDAPConnection::SearchByDN(const std::wstring& dn, Entry& outEntry)
    {
        if (ldapConnection == NULL) return false;

        LDAPMessage* pSearchResult = NULL;
        struct l_timeval timeout { 1000, 0 };

        unsigned long returnCode = ldap_search_ext_sW(
            ldapConnection,
            const_cast<wchar_t*>(dn.c_str()),
            0, // LDAP_SCOPE_BASE
            const_cast<wchar_t*>(L"(objectClass=*)"),
            NULL,
            0,
            NULL,
            NULL,
            &timeout,
            1,
            &pSearchResult);

        if (returnCode != 0 || !pSearchResult)
        {
            if (pSearchResult) ldap_msgfree(pSearchResult);
            return false;
        }

        LDAPMessage* pEntry = ldap_first_entry(ldapConnection, pSearchResult);
        if (!pEntry)
        {
            ldap_msgfree(pSearchResult);
            return false;
        }

        wchar_t* dnResult = ldap_get_dnW(ldapConnection, pEntry);
        outEntry.dn = dnResult ? dnResult : L"";
        if (dnResult) ldap_memfree(dnResult);

        BerElement* pBer = NULL;
        wchar_t* attribute = ldap_first_attributeW(ldapConnection, pEntry, &pBer);
        while (attribute != NULL)
        {
            wchar_t** vals = ldap_get_valuesW(ldapConnection, pEntry, attribute);
            struct berval** bvals = ldap_get_values_lenW(ldapConnection, pEntry, attribute);
            int valCount = vals ? ldap_count_valuesW(vals) : 0;

            std::vector<std::wstring> fvals;
            for (int i = 0; i < valCount; ++i)
            {
                std::wstring fval = Converters::FormatAttributeValue(
                    std::wstring(attribute), vals[i], bvals && bvals[i] ? bvals[i] : nullptr);
                fvals.push_back(fval);
            }

            if (!fvals.empty())
            {
                outEntry.attrs[attribute] = std::move(fvals);
            }

            if (vals) ldap_value_freeW(vals);
            if (bvals) ldap_value_free_len(bvals);
            ldap_memfree(attribute);
            attribute = ldap_next_attributeW(ldapConnection, pEntry, pBer);
        }
        if (pBer) ber_free(pBer, 0);

        ldap_msgfree(pSearchResult);
        return true;
    }

    void LDAPConnection::SearchByAttribute(const std::wstring& attrName, const std::wstring& attrValue,
        const SearchConfig& config, std::vector<Entry>& outEntries)
    {
        if (ldapConnection == NULL) return;

        // Build filter: (attrName=attrValue)
        std::wstring customFilter = L"(" + attrName + L"=" + attrValue + L")";

        SearchConfig modifiedConfig = config;
        modifiedConfig.filter = customFilter;

        Statistics tempStats;
        Search(modifiedConfig, outEntries, tempStats);
    }

    void LDAPConnection::Search(const SearchConfig& config, std::vector<Entry>& outEntries, Statistics& outStats)
    {
        if (ldapConnection == NULL)
        {
            std::cerr << "Not connected to LDAP." << std::endl;
            return;
        }

        bool collectForExport = (config.format != OutputFormat::CONSOLE_ONLY && !config.outputFile.empty());
        bool isWildcard = !config.attributesStr.empty() && config.attributesStr == L"*";

        std::vector<Entry> entries;
        std::set<std::wstring> allAttributes;

        // Parse attributes
        std::vector<std::wstring> attributes;
        if (isWildcard)
        {
            attributes.push_back(L"*");
        }
        else
        {
            std::wstringstream ss(config.attributesStr);
            std::wstring attr;
            while (std::getline(ss, attr, L','))
            {
                attr.erase(0, attr.find_first_not_of(L" \t"));
                attr.erase(attr.find_last_not_of(L" \t") + 1);
                if (!attr.empty())
                    attributes.push_back(attr);
            }
        }

        LDAPMessage* pSearchResult = NULL;
        std::vector<wchar_t*> attrList;
        if (!isWildcard)
        {
            for (const auto& attr : attributes)
                attrList.push_back(const_cast<wchar_t*>(attr.c_str()));
            attrList.push_back(NULL);
        }

        struct l_timeval timeout { 1000, 0 };
        unsigned long pageSize = 1000;
        LDAPControlW pageControl{ const_cast<wchar_t*>(L"1.2.840.113556.1.4.319"), {0}, FALSE };
        LDAPControlW* serverControls[] = { &pageControl, NULL };
        LDAPControlW* clientControls[] = { NULL };
        struct berval cookie = { 0, NULL };
        bool morePages = true;
        int totalEntries = 0;

        std::wcout << L"***Searching..." << std::endl;
        std::wcout << L"Base DN: \"" << config.baseDN << L"\"" << std::endl;
        std::wcout << L"Filter: \"" << config.filter << L"\"" << std::endl;
        std::wcout << L"Scope: " << config.scope << std::endl << std::endl;

        while (morePages)
        {
            struct berval pageSizeBerval { static_cast<int>(sizeof(unsigned long)), reinterpret_cast<char*>(&pageSize) };
            pageControl.ldctl_value = pageSizeBerval;

            unsigned long returnCode = ldap_search_ext_sW(
                ldapConnection,
                const_cast<wchar_t*>(config.baseDN.c_str()),
                config.scope,
                const_cast<wchar_t*>(config.filter.c_str()),
                isWildcard ? NULL : attrList.data(),
                0,
                serverControls,
                clientControls,
                &timeout,
                config.sizeLimit,
                &pSearchResult);

            if (returnCode != 0 && returnCode != 4) // LDAP_SIZELIMIT_EXCEEDED
            {
                std::wcerr << L"LDAP search error. Code: " << returnCode << std::endl;
                if (pSearchResult) ldap_msgfree(pSearchResult);
                if (cookie.bv_val) free(cookie.bv_val);
                return;
            }

            int entryCount = ldap_count_entries(ldapConnection, pSearchResult);
            totalEntries += entryCount;
            std::wcout << L"Found " << entryCount << L" entries in this page (Total: " << totalEntries << L")" << std::endl;

            if (entryCount == 0)
            {
                ldap_msgfree(pSearchResult);
                if (cookie.bv_val) free(cookie.bv_val);
                break;
            }

            int currentEntry = totalEntries - entryCount + 1;
            LDAPMessage* pEntry = ldap_first_entry(ldapConnection, pSearchResult);
            while (pEntry != NULL)
            {
                wchar_t* dn = ldap_get_dnW(ldapConnection, pEntry);
                std::wstring dn_str = dn ? dn : L"";
                ldap_memfree(dn);

                std::wcout << L"\nEntry " << currentEntry << L"/" << totalEntries << L":" << std::endl;
                std::wcout << L"DN: " << dn_str << std::endl;

                Entry e;
                e.dn = dn_str;

                BerElement* pBer = NULL;
                wchar_t* attribute = ldap_first_attributeW(ldapConnection, pEntry, &pBer);
                while (attribute != NULL)
                {
                    if (collectForExport)
                    {
                        allAttributes.insert(attribute);
                    }

                    wchar_t** vals = ldap_get_valuesW(ldapConnection, pEntry, attribute);
                    struct berval** bvals = ldap_get_values_lenW(ldapConnection, pEntry, attribute);
                    int valCount = vals ? ldap_count_valuesW(vals) : 0;

                    std::vector<std::wstring> fvals;
                    for (int i = 0; i < valCount; ++i)
                    {
                        std::wstring fval = Converters::FormatAttributeValue(
                            std::wstring(attribute), vals[i], bvals && bvals[i] ? bvals[i] : nullptr);
                        fvals.push_back(fval);
                    }

                    if (!fvals.empty())
                    {
                        e.attrs[attribute] = std::move(fvals);
                    }

                    std::wcout << L"  " << attribute;
                    if (valCount > 1)
                        std::wcout << L" (" << valCount << L")";
                    std::wcout << L": ";
                    for (int i = 0; i < valCount; ++i)
                    {
                        if (i > 0) std::wcout << L"; ";
                        std::wcout << e.attrs[attribute][i];
                    }
                    std::wcout << L";" << std::endl;

                    if (vals) ldap_value_freeW(vals);
                    if (bvals) ldap_value_free_len(bvals);
                    ldap_memfree(attribute);
                    attribute = ldap_next_attributeW(ldapConnection, pEntry, pBer);
                }
                if (pBer) ber_free(pBer, 0);

                if (collectForExport)
                {
                    entries.push_back(std::move(e));
                }

                std::wcout << L"\n" << std::wstring(70, L'=') << std::endl;

                pEntry = ldap_next_entry(ldapConnection, pEntry);
                ++currentEntry;
            }

            LDAPControlW** returnedControls = NULL;
            if (ldap_parse_resultW(ldapConnection, pSearchResult, NULL, NULL, NULL, NULL, &returnedControls, FALSE) == 0)
            {
                for (unsigned long i = 0; returnedControls && returnedControls[i]; ++i)
                {
                    if (wcscmp(returnedControls[i]->ldctl_oid, L"1.2.840.113556.1.4.319") == 0)
                    {
                        cookie.bv_len = returnedControls[i]->ldctl_value.bv_len;
                        if (cookie.bv_len > 0)
                        {
                            cookie.bv_val = (char*)malloc(cookie.bv_len);
                            if (cookie.bv_val)
                                memcpy(cookie.bv_val, returnedControls[i]->ldctl_value.bv_val, cookie.bv_len);
                            else
                                morePages = false;
                        }
                        else
                        {
                            morePages = false;
                        }
                        break;
                    }
                }
                ldap_controls_freeW(returnedControls);
            }

            ldap_msgfree(pSearchResult);
            pSearchResult = NULL;

            if (cookie.bv_val)
            {
                pageControl.ldctl_value = cookie;
            }
            else
            {
                morePages = false;
            }
        }

        if (cookie.bv_val) free(cookie.bv_val);

        std::wcout << L"\nTotal entries found: " << totalEntries << std::endl;

        // Calculate statistics
        outStats = StatisticsCalculator::Calculate(entries);
        StatisticsCalculator::PrintStatistics(outStats);

        // Export if needed
        if (collectForExport && !entries.empty())
        {
            std::vector<std::wstring> exportAttributes = isWildcard ?
                std::vector<std::wstring>(allAttributes.begin(), allAttributes.end()) : attributes;

            std::wcout << L"\n*** Exporting results..." << std::endl;
            std::wcout << L"Format: ";

            switch (config.format)
            {
            case OutputFormat::CSV:
                std::wcout << L"CSV" << std::endl;
                Exporter::ExportCsv(config.outputFile, exportAttributes, entries);
                break;
            case OutputFormat::TXT:
                std::wcout << L"TXT" << std::endl;
                Exporter::ExportTxt(config.outputFile, entries);
                break;
            case OutputFormat::JSON:
                std::wcout << L"JSON" << std::endl;
                Exporter::ExportJson(config.outputFile, entries);
                break;
            case OutputFormat::XML:
                std::wcout << L"XML" << std::endl;
                Exporter::ExportXml(config.outputFile, entries);
                break;
            case OutputFormat::HTML:
                std::wcout << L"HTML (Interactive UI)" << std::endl;
                Exporter::ExportHtml(config.outputFile, exportAttributes, entries, outStats);
                break;
            default:
                break;
            }

            std::wcout << L"✓ Export successful: " << config.outputFile << std::endl;
            std::wcout << L"  Total entries: " << entries.size() << std::endl;
            std::wcout << L"  Total attributes: " << exportAttributes.size() << std::endl;
        }

        outEntries = std::move(entries);
    }
}