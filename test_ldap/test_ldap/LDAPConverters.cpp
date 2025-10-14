#include "LDAPConverters.h"
#include <algorithm>
#include <sddl.h>
#include <winldap.h>
#include <iomanip>
#include <winber.h>

namespace LDAPUtils
{
    std::wstring Converters::BinaryToHexString(const unsigned char* data, unsigned long length)
    {
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        for (unsigned long i = 0; i < length; ++i)
        {
            ss << L"\\x" << std::setw(2) << (int)data[i];
        }
        return ss.str();
    }

    std::wstring Converters::ConvertFileTimeToLocal(unsigned long long fileTimeTicks)
    {
        FILETIME fileTime;
        fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
        fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

        SYSTEMTIME utcSystemTime, localTime;
        FileTimeToSystemTime(&fileTime, &utcSystemTime);

        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
            << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
            << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
            << std::setw(2) << localTime.wSecond;
        return ss.str();
    }

    std::wstring Converters::ConvertLDAPTimeToLocal(const std::wstring& ldapTime)
    {
        if (ldapTime.empty()) return L"";
        SYSTEMTIME utcSystemTime = { 0 };
        utcSystemTime.wYear = std::stoi(ldapTime.substr(0, 4));
        utcSystemTime.wMonth = std::stoi(ldapTime.substr(4, 2));
        utcSystemTime.wDay = std::stoi(ldapTime.substr(6, 2));
        utcSystemTime.wHour = std::stoi(ldapTime.substr(8, 2));
        utcSystemTime.wMinute = std::stoi(ldapTime.substr(10, 2));
        utcSystemTime.wSecond = std::stoi(ldapTime.substr(12, 2));

        SYSTEMTIME localTime;
        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
            << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
            << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
            << std::setw(2) << localTime.wSecond;
        return ss.str();
    }

    std::wstring Converters::ConvertTicksToDuration(long long ticks)
    {
        ticks = -ticks;
        long long seconds = ticks / 10000000;
        int days = static_cast<int>(seconds / 86400);
        int hours = static_cast<int>((seconds % 86400) / 3600);
        int minutes = static_cast<int>((seconds % 3600) / 60);
        int secs = static_cast<int>(seconds % 60);
        std::wstringstream ss;
        ss << days << L":" << std::setfill(L'0') << std::setw(2) << hours << L":"
            << std::setw(2) << minutes << L":" << std::setw(2) << secs;
        return ss.str();
    }

    std::wstring Converters::ConvertGUIDToString(const unsigned char* guid, unsigned long length)
    {
        if (length != 16) return L"Invalid GUID";
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        ss << std::setw(2) << (int)guid[3] << std::setw(2) << (int)guid[2]
            << std::setw(2) << (int)guid[1] << std::setw(2) << (int)guid[0] << L"-"
            << std::setw(2) << (int)guid[5] << std::setw(2) << (int)guid[4] << L"-"
            << std::setw(2) << (int)guid[7] << std::setw(2) << (int)guid[6] << L"-"
            << std::setw(2) << (int)guid[8] << std::setw(2) << (int)guid[9] << L"-";
        for (int i = 10; i < 16; i++)
            ss << std::setw(2) << (int)guid[i];
        return ss.str();
    }

    std::wstring Converters::ConvertSIDToString(const unsigned char* sid, unsigned long length)
    {
        PSID psid = (PSID)sid;
        LPWSTR sidString = NULL;
        if (ConvertSidToStringSidW(psid, &sidString))
        {
            std::wstring result(sidString);
            LocalFree(sidString);
            return result;
        }
        return L"Invalid SID";
    }

    std::wstring Converters::ConvertDSASignature(const unsigned char* data, unsigned long length, bool debug)
    {
        if (data == nullptr || length < 40) return L"<Invalid dSASignature>";

        const unsigned char* guidData = data + 24;
        std::wstringstream guidStr;
        guidStr << std::hex << std::setfill(L'0');
        guidStr << std::setw(2) << (int)guidData[3] << std::setw(2) << (int)guidData[2]
            << std::setw(2) << (int)guidData[1] << std::setw(2) << (int)guidData[0] << L"-"
            << std::setw(2) << (int)guidData[5] << std::setw(2) << (int)guidData[4] << L"-"
            << std::setw(2) << (int)guidData[7] << std::setw(2) << (int)guidData[6] << L"-"
            << std::setw(2) << (int)guidData[8] << std::setw(2) << (int)guidData[9] << L"-"
            << std::setw(2) << (int)guidData[10] << std::setw(2) << (int)guidData[11]
            << std::setw(2) << (int)guidData[12] << std::setw(2) << (int)guidData[13]
            << std::setw(2) << (int)guidData[14] << std::setw(2) << (int)guidData[15];

        return L"{ V1: DsaGuid = " + guidStr.str() + L" }";
    }

    std::wstring Converters::ToLower(const std::wstring& str)
    {
        std::wstring lowerStr = str;
        std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), towlower);
        return lowerStr;
    }

    std::wstring Converters::GetInstanceTypeDescription(int value)
    {
        std::wstring desc;
        if (value & 0x1) desc += L"IS_NC_HEAD | ";
        if (value & 0x4) desc += L"WRITE | ";
        if (!desc.empty()) desc = L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring Converters::GetSystemFlagsDescription(int value)
    {
        std::wstring desc;
        if (value & 0x80000000) desc += L"DISALLOW_DELETE | ";
        if (value & 0x4000000) desc += L"DOMAIN_DISALLOW_RENAME | ";
        if (value & 0x8000000) desc += L"DOMAIN_DISALLOW_MOVE | ";
        if (!desc.empty()) desc = L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring Converters::GetUserAccountControlDescription(int value)
    {
        std::wstring desc;
        if (value & 0x00000002) desc += L"ACCOUNTDISABLE | ";
        if (value & 0x00000010) desc += L"LOCKOUT | ";
        if (value & 0x00000200) desc += L"NORMAL_ACCOUNT | ";
        if (value & 0x00010000) desc += L"DONT_EXPIRE_PASSWORD | ";
        if (!desc.empty())
        {
            desc = desc.substr(0, desc.length() - 3);
            return L" = ( " + desc + L" )";
        }
        return L"= (  )";
    }

    std::wstring Converters::GetGroupTypeDescription(int value)
    {
        std::wstring desc;
        if (value & 0x00000002) desc += L"ACCOUNT_GROUP | ";
        if (value & 0x80000000) desc += L"SECURITY_ENABLED | ";
        if (!desc.empty())
        {
            desc = desc.substr(0, desc.length() - 3);
            return L" = ( " + desc + L" )";
        }
        return L"= (  )";
    }

    std::wstring Converters::GetSAMAccountTypeDescription(int value)
    {
        switch (value)
        {
        case 805306368: return L"= ( NORMAL_USER_ACCOUNT )";
        case 805306369: return L"= ( MACHINE_ACCOUNT )";
        case 268435456: return L"= ( GROUP_OBJECT )";
        default: return L"= ( UNKNOWN )";
        }
    }

    std::wstring LDAPUtils::Converters::FormatAttributeValue(const std::wstring& attrName, wchar_t* val, struct berval* bval)
    {
        if (!val) return L"";

        std::wstringstream output;
        bool isBinary = (bval && bval->bv_len > 0 && val[0] == L'\0');

        if (attrName == L"dSASignature" && bval)
        {
            output << ConvertDSASignature((unsigned char*)bval->bv_val, bval->bv_len, false);
        }
        else if (isBinary)
        {
            output << L"<Binary " << bval->bv_len << L" bytes>";
        }
        else
        {
            output << val;
        }

        if (attrName == L"whenCreated" || attrName == L"whenChanged")
        {
            output.str(L"");
            output << ConvertLDAPTimeToLocal(val);
        }
        else if (attrName == L"lastLogonTimestamp" || attrName == L"lastLogon")
        {
            output.str(L"");
            unsigned long long ticks = _wtoi64(val);
            output << (ticks == 0 ? L"0" : ConvertFileTimeToLocal(ticks));
        }
        else if (ToLower(attrName).find(L"guid") != std::wstring::npos && bval)
        {
            output.str(L"");
            output << ConvertGUIDToString((unsigned char*)bval->bv_val, bval->bv_len);
        }
        else if (ToLower(attrName).find(L"sid") != std::wstring::npos && bval)
        {
            output.str(L"");
            output << ConvertSIDToString((unsigned char*)bval->bv_val, bval->bv_len);
        }
        else if (attrName == L"instanceType")
        {
            output.str(L"");
            int value = static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << L" " << GetInstanceTypeDescription(value);
        }
        else if (attrName == L"systemFlags")
        {
            output.str(L"");
            int value = static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << L" " << GetSystemFlagsDescription(value);
        }
        else if (attrName == L"userAccountControl")
        {
            output.str(L"");
            int value = static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << GetUserAccountControlDescription(value);
        }
        else if (attrName == L"groupType")
        {
            output.str(L"");
            int value = static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << GetGroupTypeDescription(value);
        }
        else if (attrName == L"sAMAccountType")
        {
            output.str(L"");
            int value = static_cast<int>(_wtol(val));
            output << value << L" " << GetSAMAccountTypeDescription(value);
        }

        return output.str();
    }

    std::string Converters::WStringToUtf8(const std::wstring& ws)
    {
        if (ws.empty()) return std::string();
        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.length()), nullptr, 0, nullptr, nullptr);
        std::string utf8(len, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.length()), &utf8[0], len, nullptr, nullptr);
        return utf8;
    }

    std::wstring Converters::StringToWString(const std::string& str)
    {
        if (str.empty()) return std::wstring();
        int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
        std::wstring wstr(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &wstr[0], len);
        return wstr;
    }
}
