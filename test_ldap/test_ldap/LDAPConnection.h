#pragma once
#include "LDAPTypes.h"
#include <windows.h>
#include <winldap.h>

#pragma comment(lib, "wldap32.lib")

namespace LDAPUtils
{
    class LDAPConnection
    {
    private:
        LDAP* ldapConnection;

    public:
        LDAPConnection(const std::wstring& serverAddress, unsigned long port = 389);
        ~LDAPConnection();

        bool Connect(const std::wstring& username, const std::wstring& password, const std::wstring& domain);
        void Disconnect();

        void Search(const SearchConfig& config, std::vector<Entry>& outEntries, Statistics& outStats);
        bool SearchByDN(const std::wstring& dn, Entry& outEntry);
        void SearchByAttribute(const std::wstring& attrName, const std::wstring& attrValue,
            const SearchConfig& config, std::vector<Entry>& outEntries);
    };
}