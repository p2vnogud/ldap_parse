#pragma once
#include <string>
#include <sstream>
#include <windows.h>
#include <winldap.h>
#include <winber.h>

namespace LDAPUtils
{
    class Converters
    {
    public:
        static std::wstring BinaryToHexString(const unsigned char* data, unsigned long length);
        static std::wstring ConvertFileTimeToLocal(unsigned long long fileTimeTicks);
        static std::wstring ConvertLDAPTimeToLocal(const std::wstring& ldapTime);
        static std::wstring ConvertTicksToDuration(long long ticks);
        static std::wstring ConvertGUIDToString(const unsigned char* guid, unsigned long length);
        static std::wstring ConvertSIDToString(const unsigned char* sid, unsigned long length);
        static std::wstring ConvertDSASignature(const unsigned char* data, unsigned long length, bool debug = false);
        static std::wstring ToLower(const std::wstring& str);

        // Descriptions
        static std::wstring GetInstanceTypeDescription(int value);
        static std::wstring GetSystemFlagsDescription(int value);
        static std::wstring GetUserAccountControlDescription(int value);
        static std::wstring GetGroupTypeDescription(int value);
        static std::wstring GetSAMAccountTypeDescription(int value);

        // Format attribute value
        static std::wstring FormatAttributeValue(const std::wstring& attrName, wchar_t* val, struct berval* bval);

        // String conversions
        static std::string WStringToUtf8(const std::wstring& ws);
        static std::wstring StringToWString(const std::string& str);
    };
}