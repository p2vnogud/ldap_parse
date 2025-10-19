#include <iostream>
#include <windows.h>
#include <winldap.h>
#include <ntdsapi.h>
#include <winber.h>
#include <sddl.h>
#include <vector>
#include <fcntl.h>
#include <io.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <stdlib.h>
#include <ctime>

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "advapi32.lib")

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

    struct Entry
    {
        std::wstring dn;
        std::map<std::wstring, std::vector<std::wstring>> attrs;
    };

    std::wstring BinaryToHexString(const unsigned char* data, ULONG length)
    {
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        for (ULONG i=0; i < length; ++i)
        {
            ss << L"\\x" << std::setw(2) << (int)data[i];
        }
        return ss.str();
    }

    std::wstring ConvertFileTimeToLocal(ULONGLONG fileTimeTicks)
    {
        FILETIME fileTime;
        fileTime.dwLowDateTime=static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
        fileTime.dwHighDateTime=static_cast<DWORD>(fileTimeTicks >> 32);

        SYSTEMTIME utcSystemTime;
        FileTimeToSystemTime(&fileTime, &utcSystemTime);

        SYSTEMTIME localTime;
        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
            << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
            << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
            << std::setw(2) << localTime.wSecond << L" " << (localTime.wHour < 12 ? L"AM" : L"PM") << L" SE Asia Standard Time";
        return ss.str();
    }

    std::wstring ToLower(const std::wstring& str)
    {
        std::wstring lowerStr=str;
        std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), towlower);
        return lowerStr;
    }

    std::wstring ConvertLDAPTimeToLocal(const std::wstring& ldapTime)
    {
        if (ldapTime.empty())
            return L"";
        SYSTEMTIME utcSystemTime={ 0 };
        utcSystemTime.wYear=std::stoi(ldapTime.substr(0, 4));
        utcSystemTime.wMonth=std::stoi(ldapTime.substr(4, 2));
        utcSystemTime.wDay=std::stoi(ldapTime.substr(6, 2));
        utcSystemTime.wHour=std::stoi(ldapTime.substr(8, 2));
        utcSystemTime.wMinute=std::stoi(ldapTime.substr(10, 2));
        utcSystemTime.wSecond=std::stoi(ldapTime.substr(12, 2));

        SYSTEMTIME localTime;
        TIME_ZONE_INFORMATION tzInfo;
        GetTimeZoneInformation(&tzInfo);
        SystemTimeToTzSpecificLocalTime(&tzInfo, &utcSystemTime, &localTime);

        std::wstringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << localTime.wMonth << L"/"
            << std::setw(2) << localTime.wDay << L"/" << localTime.wYear << L" "
            << std::setw(2) << localTime.wHour << L":" << std::setw(2) << localTime.wMinute << L":"
            << std::setw(2) << localTime.wSecond << L" " << (localTime.wHour < 12 ? L"AM" : L"PM") << L" SE Asia Standard Time";
        return ss.str();
    }

    std::wstring GetInstanceTypeDescription(int value)
    {
        std::wstring desc;
        if (value & 0x1) desc += L"IS_NC_HEAD | ";
        if (value & 0x4) desc += L"WRITE | ";
        if (!desc.empty()) desc=L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring GetSystemFlagsDescription(int value)
    {
        std::wstring desc;
        if (value & 0x80000000) desc += L"DISALLOW_DELETE | ";
        if (value & 0x4000000) desc += L"DOMAIN_DISALLOW_RENAME | ";
        if (value & 0x8000000) desc += L"DOMAIN_DISALLOW_MOVE | ";
        if (!desc.empty()) desc=L"= ( " + desc.substr(0, desc.length() - 3) + L" )";
        return desc;
    }

    std::wstring ConvertDSASignature(const unsigned char* data, ULONG length, bool debug=false)
    {
        if (data == nullptr || length < 40)
        {
            return L"<Invalid dSASignature>";
        }

        const unsigned char* guidData=data + 24;
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

        std::wstringstream ss;
        ss << L"{ V1: DsaGuid=" << guidStr.str() << L" }";
        return ss.str();
    }

    std::wstring ConvertGUIDToString(const unsigned char* guid, ULONG length)
    {
        if (length != 16) return L"Invalid GUID";
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        ss << std::setw(2) << (int)guid[3] << std::setw(2) << (int)guid[2] << std::setw(2) << (int)guid[1] << std::setw(2) << (int)guid[0] << L"-"
            << std::setw(2) << (int)guid[5] << std::setw(2) << (int)guid[4] << L"-"
            << std::setw(2) << (int)guid[7] << std::setw(2) << (int)guid[6] << L"-"
            << std::setw(2) << (int)guid[8] << std::setw(2) << (int)guid[9] << L"-";
        for (int i=10; i < 16; i++)
            ss << std::setw(2) << (int)guid[i];
        return ss.str();
    }

    std::wstring ConvertSIDToString(const unsigned char* sid, ULONG length)
    {
        PSID psid=(PSID)sid;
        LPWSTR sidString=NULL;
        if (ConvertSidToStringSidW(psid, &sidString))
        {
            std::wstring result(sidString);
            LocalFree(sidString);
            return result;
        }
        return L"Invalid SID";
    }

    std::wstring GetSAMAccountTypeDescription(int value)
    {
        switch (value)
        {
        case 805306368: return L"= ( NORMAL_USER_ACCOUNT )";
        case 805306369: return L"= ( MACHINE_ACCOUNT )";
        case 268435456: return L"= ( GROUP_OBJECT )";
        default: return L"= ( UNKNOWN )";
        }
    }

    std::wstring GetUserAccountControlDescription(int value)
    {
        std::wstring desc;
        if (value & 0x00000002) desc += L"ACCOUNTDISABLE | ";
        if (value & 0x00000010) desc += L"LOCKOUT | ";
        if (value & 0x00000200) desc += L"NORMAL_ACCOUNT | ";
        if (value & 0x00010000) desc += L"DONT_EXPIRE_PASSWORD | ";
        if (!desc.empty())
        {
            desc=desc.substr(0, desc.length() - 3);
            return L"=( " + desc + L" )";
        }
        return L"= (  )";
    }

    std::wstring GetGroupTypeDescription(int value)
    {
        std::wstring desc;
        if (value & 0x00000002) desc += L"ACCOUNT_GROUP | ";
        if (value & 0x80000000) desc += L"SECURITY_ENABLED | ";
        if (!desc.empty())
        {
            desc=desc.substr(0, desc.length() - 3);
            return L"=( " + desc + L" )";
        }
        return L"= (  )";
    }

    std::string WStringToUtf8(const std::wstring& ws)
    {
        if (ws.empty()) return std::string();
        int len=WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.length()), nullptr, 0, nullptr, nullptr);
        std::string utf8(len, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.length()), &utf8[0], len, nullptr, nullptr);
        return utf8;
    }

    std::string EscapeCsvField(const std::string& input)
    {
        std::string output="\"";
        for (char c : input)
        {
            if (c == '"') output += "\"\"";
            else output += c;
        }
        output += "\"";
        return output;
    }

    std::string EscapeJson(const std::string& input)
    {
        std::string output;
        for (char c : input)
        {
            switch (c)
            {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c;
            }
        }
        return output;
    }

    std::string EscapeXml(const std::string& input)
    {
        std::string output;
        for (char c : input)
        {
            switch (c)
            {
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '&': output += "&amp;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&apos;"; break;
            default: output += c;
            }
        }
        return output;
    }

    std::string EscapeHtml(const std::string& input)
    {
        return EscapeXml(input);
    }

    std::wstring FormatAttributeValue(const std::wstring& attrName, PWCHAR val, struct berval* bval)
    {
        if (!val) return L"";

        std::wstringstream output;
        bool isBinary=(bval && bval->bv_len > 0 && val[0] == L'\0');

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
            ULONGLONG ticks=_wtoi64(val);
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
            int value=static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << L" " << GetInstanceTypeDescription(value);
        }
        else if (attrName == L"systemFlags")
        {
            output.str(L"");
            int value=static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << L" " << GetSystemFlagsDescription(value);
        }
        else if (attrName == L"userAccountControl")
        {
            output.str(L"");
            int value=static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << GetUserAccountControlDescription(value);
        }
        else if (attrName == L"groupType")
        {
            output.str(L"");
            int value=static_cast<int>(_wtol(val));
            output << L"0x" << std::hex << value << GetGroupTypeDescription(value);
        }
        else if (attrName == L"sAMAccountType")
        {
            output.str(L"");
            int value=static_cast<int>(_wtol(val));
            output << value << L" " << GetSAMAccountTypeDescription(value);
        }

        return output.str();
    }

    void WriteCsvFile(const std::wstring& filename, const std::vector<std::wstring>& attributes, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Cannot open CSV file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        std::string header=EscapeCsvField("DN");
        for (const auto& attr : attributes)
        {
            header += "," + EscapeCsvField(WStringToUtf8(attr));
        }
        header += "\n";
        file << header;

        for (const auto& e : entries)
        {
            std::string row=EscapeCsvField(WStringToUtf8(e.dn));
            for (const auto& attr : attributes)
            {
                std::wstring joined;
                auto it=e.attrs.find(attr);
                if (it != e.attrs.end() && !it->second.empty())
                {
                    for (size_t k=0; k < it->second.size(); ++k)
                    {
                        if (k > 0) joined += L" | ";
                        joined += it->second[k];
                    }
                }
                row += "," + EscapeCsvField(WStringToUtf8(joined));
            }
            row += "\n";
            file << row;
        }
        file.close();
    }

    void WriteTxtFile(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Cannot open TXT file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        for (size_t i=0; i < entries.size(); ++i)
        {
            const auto& e=entries[i];
            file << "Entry " << (i + 1) << ":\n";
            file << "DN: " << WStringToUtf8(e.dn) << "\n";

            for (const auto& attr : e.attrs)
            {
                file << "  " << WStringToUtf8(attr.first);
                if (attr.second.size() > 1)
                    file << " (" << attr.second.size() << ")";
                file << ": ";

                for (size_t j=0; j < attr.second.size(); ++j)
                {
                    if (j > 0) file << "; ";
                    file << WStringToUtf8(attr.second[j]);
                }
                file << "\n";
            }
            file << "\n" << std::string(70, '=') << "\n\n";
        }
        file.close();
    }

    void WriteJsonFile(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Cannot open JSON file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        file << "{\n  \"entries\": [\n";

        for (size_t i=0; i < entries.size(); ++i)
        {
            const auto& e=entries[i];
            file << "    {\n";
            file << "      \"dn\": \"" << EscapeJson(WStringToUtf8(e.dn)) << "\",\n";
            file << "      \"attributes\": {\n";

            size_t attrCount=0;
            for (const auto& attr : e.attrs)
            {
                if (attrCount > 0) file << ",\n";
                file << "        \"" << EscapeJson(WStringToUtf8(attr.first)) << "\": [";

                for (size_t j=0; j < attr.second.size(); ++j)
                {
                    if (j > 0) file << ", ";
                    file << "\"" << EscapeJson(WStringToUtf8(attr.second[j])) << "\"";
                }
                file << "]";
                attrCount++;
            }
            file << "\n      }\n    }";
            if (i < entries.size() - 1) file << ",";
            file << "\n";
        }

        file << "  ]\n}\n";
        file.close();
    }

    void WriteXmlFile(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Cannot open XML file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        file << "<ldap_results>\n";

        for (const auto& e : entries)
        {
            file << "  <entry>\n";
            file << "    <dn>" << EscapeXml(WStringToUtf8(e.dn)) << "</dn>\n";
            file << "    <attributes>\n";

            for (const auto& attr : e.attrs)
            {
                for (const auto& val : attr.second)
                {
                    file << "      <attribute name=\"" << EscapeXml(WStringToUtf8(attr.first)) << "\">"
                        << EscapeXml(WStringToUtf8(val)) << "</attribute>\n";
                }
            }

            file << "    </attributes>\n";
            file << "  </entry>\n";
        }

        file << "</ldap_results>\n";
        file.close();
    }

    void WriteHtmlFile(const std::wstring& filename, const std::vector<std::wstring>& attributes, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Cannot open HTML file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";

        time_t now=time(0);
        tm ltm;
        localtime_s(&ltm, &now);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &ltm);

        file << R"(<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDAP Query Results - Advanced Viewer</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            overflow: hidden;
        }
        
        .main-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            max-width: 1920px;
            margin: 0 auto;
            background: white;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            flex-shrink: 0;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }
        
        .header h1 {
            font-size: 24px;
            margin-bottom: 8px;
        }
        
        .header-info {
            font-size: 13px;
            opacity: 0.95;
        }
        
        /* Control Panel */
        .control-panel {
            background: #f8f9ff;
            padding: 15px 30px;
            border-bottom: 2px solid #e0e0e0;
            flex-shrink: 0;
        }
        
        .control-row {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .control-row:last-child {
            margin-bottom: 0;
        }
        
        .search-group {
            flex: 1;
            min-width: 300px;
            display: flex;
            gap: 10px;
        }
        
        .search-box {
            flex: 1;
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .search-box:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        
        .select-box {
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            background: white;
            cursor: pointer;
            min-width: 150px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            white-space: nowrap;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102,126,234,0.4);
        }
        
        .btn-success { background: linear-gradient(135deg, #56ab2f 0%, #a8e063 100%); }
        .btn-info { background: linear-gradient(135deg, #2196F3 0%, #21CBF3 100%); }
        .btn-warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .btn-secondary { background: linear-gradient(135deg, #6c757d 0%, #495057 100%); }
        
        /* Stats Panel */
        .stats-panel {
            background: white;
            padding: 15px 30px;
            border-bottom: 2px solid #e0e0e0;
            flex-shrink: 0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f8f9ff 0%, #f0f2ff 100%);
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        
        .stat-label {
            font-size: 11px;
            color: #666;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #667eea;
            margin-top: 5px;
        }
        
        /* Content Area */
        .content-area {
            flex: 1;
            display: flex;
            overflow: hidden;
            position: relative;
        }
        
        /* Table Container */
        .table-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background: white;
        }
        
        .table-wrapper {
            flex: 1;
            overflow: auto;
            position: relative;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        
        thead {
            position: sticky;
            top: 0;
            z-index: 10;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        th {
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            color: white;
            white-space: nowrap;
            cursor: pointer;
            user-select: none;
            font-size: 13px;
            border-right: 1px solid rgba(255,255,255,0.1);
        }
        
        th:hover {
            background: rgba(255,255,255,0.1);
        }
        
        th.sortable::after {
            content: '⇅';
            margin-left: 5px;
            opacity: 0.5;
            font-size: 12px;
        }
        
        th.sorted-asc::after {
            content: '↑';
            opacity: 1;
        }
        
        th.sorted-desc::after {
            content: '↓';
            opacity: 1;
        }
        
        td {
            padding: 10px;
            border-bottom: 1px solid #f0f0f0;
            font-size: 13px;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        tbody tr:hover {
            background: linear-gradient(135deg, #f8f9ff 0%, #f0f2ff 100%);
        }
        
        .highlight {
            background: #fff176;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: 600;
        }
        
        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            padding: 15px;
            background: #f8f9ff;
            border-top: 2px solid #e0e0e0;
            flex-shrink: 0;
        }
        
        .page-btn {
            padding: 8px 14px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            transition: all 0.3s;
        }
        
        .page-btn:hover:not(:disabled) {
            background: #667eea;
            color: white;
        }
        
        .page-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        
        .page-btn.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            overflow: auto;
        }
        
        .modal-content {
            background: white;
            margin: 30px auto;
            padding: 30px;
            width: 95%;
            max-width: 1200px;
            border-radius: 15px;
            max-height: calc(100vh - 60px);
            overflow-y: auto;
            position: relative;
        }
        
        .modal-close {
            position: absolute;
            top: 15px;
            right: 20px;
            font-size: 30px;
            cursor: pointer;
            color: #999;
            transition: all 0.3s;
            z-index: 1;
        }
        
        .modal-close:hover {
            color: #667eea;
            transform: rotate(90deg);
        }
        
        .modal h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 22px;
        }
        
        .modal h3 {
            color: #667eea;
            margin: 20px 0 10px 0;
            font-size: 18px;
        }
        
        /* Statistics Modal */
        .stats-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
            flex-wrap: wrap;
        }
        
        .stats-tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
            font-weight: 600;
            color: #666;
        }
        
        .stats-tab:hover {
            color: #667eea;
        }
        
        .stats-tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .stats-content {
            display: none;
        }
        
        .stats-content.active {
            display: block;
        }
        
        .column-stats {
            background: #f8f9ff;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }
        
        .column-stats h4 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 16px;
        }
        
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .stat-row:last-child {
            border-bottom: none;
        }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        canvas {
            max-height: 400px;
        }
        
        /* Custom Statistics Builder */
        .custom-stats-builder {
            background: #f8f9ff;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
        }
        
        .builder-row {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .builder-label {
            font-weight: 600;
            color: #666;
            min-width: 100px;
        }
        
        .condition-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border: 2px solid #e0e0e0;
        }
        
        .condition-group input,
        .condition-group select {
            padding: 8px 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .remove-condition {
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }
        
        .stats-result {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            border: 2px solid #667eea;
        }
        
        .stats-result h4 {
            color: #667eea;
            margin-bottom: 15px;
        }
        
        /* Advanced Search */
        .search-mode-toggle {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }
        
        .mode-btn {
            padding: 8px 15px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .mode-btn.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .advanced-search {
            display: none;
            background: #f8f9ff;
            padding: 15px;
            border-radius: 10px;
            margin-top: 10px;
        }
        
        .advanced-search.active {
            display: block;
        }
        
        .search-conditions {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .search-condition {
            display: flex;
            gap: 10px;
            align-items: center;
            background: white;
            padding: 10px;
            border-radius: 8px;
        }
        
        .search-operator {
            padding: 8px 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            background: white;
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }
        
        .empty-state-icon {
            font-size: 4em;
            margin-bottom: 15px;
            opacity: 0.3;
        }
        
        /* Scrollbar Styling */
        .table-wrapper::-webkit-scrollbar {
            width: 12px;
            height: 12px;
        }
        
        .table-wrapper::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        
        .table-wrapper::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 6px;
        }
        
        .table-wrapper::-webkit-scrollbar-thumb:hover {
            background: #5568d3;
        }
        
        .modal-content::-webkit-scrollbar {
            width: 10px;
        }
        
        .modal-content::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        
        .modal-content::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 5px;
        }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 20px; }
            .control-row { flex-direction: column; }
            .search-box, .select-box { width: 100%; }
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="header">
            <h1>🔍 LDAP Query Results - Advanced Interactive Viewer</h1>
            <div class="header-info">
                📅 Generated: )" << timeStr << R"( | 📊 Total Entries: <strong id="headerTotalEntries">)" << entries.size() << R"(</strong> | 📋 Columns: <strong>)" << attributes.size() << R"(</strong>
            </div>
        </div>

        <div class="control-panel">
            <div class="control-row">
                <div class="search-mode-toggle">
                    <button class="mode-btn active" onclick="toggleSearchMode('basic')\">🔍 Basic Search</button>
                    <button class="mode-btn" onclick="toggleSearchMode('advanced')\">⚙️ Advanced Search</button>
                    <button class="mode-btn" onclick="toggleSearchMode('regex')\">🔧 Regex Search</button>
                </div>
            </div>

            <div class="control-row" id="basicSearch">
                <div class="search-group">
                    <input type="text" class="search-box" id="searchBox" placeholder="🔍 Quick search...">
                    <select class="select-box" id="columnFilter">
                        <option value="">All columns</option>
)";

        for (const auto& attr : attributes)
        {
            file << "                        <option value=\"" << EscapeHtml(WStringToUtf8(attr))
                << "\">" << EscapeHtml(WStringToUtf8(attr)) << "</option>\n";
        }

        file << R"(                    </select>
                </div>
                <select class="select-box" id="searchType">
                    <option value="contains">Contains</option>
                    <option value="equals">Equals</option>
                    <option value="startsWith">Starts with</option>
                    <option value="endsWith">Ends with</option>
                    <option value="notContains">Not contains</option>
                </select>
                <label style="display: flex; align-items: center; gap: 5px;">
                    <input type="checkbox" id="caseSensitive"> Case sensitive
                </label>
            </div>
            
            <div class="advanced-search" id="advancedSearch">
                <div class="search-conditions" id="searchConditions">
                    <div class="search-condition">
                        <select class="select-box condition-column">
                            <option value="">Select column</option>
)";

        for (const auto& attr : attributes)
        {
            file << "                            <option value=\"" << EscapeHtml(WStringToUtf8(attr))
                << "\">" << EscapeHtml(WStringToUtf8(attr)) << "</option>\n";
        }

        file << R"(                        </select>
                        <select class="search-operator">
                            <option value="contains">Contains</option>
                            <option value="equals">Equals</option>
                            <option value="startsWith">Starts with</option>
                            <option value="endsWith">Ends with</option>
                            <option value="notContains">Not contains</option>
                            <option value="gt">Greater than</option>
                            <option value="lt">Less than</option>
                            <option value="gte">Greater or equal</option>
                            <option value="lte">Less or equal</option>
                        </select>
                        <input type="text" class="search-box" placeholder="Value" style="flex: 1;">
                        <select class="search-operator">
                            <option value="AND">AND</option>
                            <option value="OR">OR</option>
                        </select>
                        <button class="remove-condition" onclick="removeCondition(this)\" style="display: none;">✖</button>
                    </div>
                </div>
                <button class="btn" onclick="addCondition()\">➕ Add Condition</button>
                <button class="btn btn-success" onclick="applyAdvancedSearch()\">🔍 Apply Search</button>
            </div>

            <div class="control-row">
                <select class="select-box" id="rowsPerPage">
                    < option value="50">50 rows/page</option>
                    < option value="100" selected>100 rows/page</option>
                    < option value="250">250 rows/page</option>
                    < option value="500">500 rows/page</option>
                    <option value="-1">All rows</option>
                </select>
                <button class="btn btn-info" onclick="showStatistics()\">📊 Statistics</button>
                <button class="btn btn-success" onclick="exportFilteredCSV()\">💾 Export CSV</button>
                <button class="btn btn-warning" onclick="exportFilteredJSON()\">📄 Export JSON</button>
                <button class="btn" onclick="clearFilter()\">🔄 Reset</button>
            </div>
        </div>

        <div class="stats-panel">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">📊 Total Rows</div>
                    <div class="stat-value" id="totalRows">)" << entries.size() << R"(</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">📋 Columns</div>
                    <div class="stat-value">)" << attributes.size() << R"(</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">🔍 Filtered</div>
                    <div class="stat-value" id="displayedRows">)" << entries.size() << R"(</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">📄 Current Page</div>
                    < div class="stat-value" id="currentPageDisplay">1 </div>
                </div>
            </div>
        </div>

        <div class="content-area">
            <div class="table-container">
                <div class="table-wrapper">
                    <table id="dataTable">
                        <thead>
                            <tr>
                                <th style="width: 60px;">#</th>
)";

        for (size_t i=0; i < attributes.size(); ++i)
        {
            file << "                                <th class=\"sortable\" onclick=\"sortTable(" << i
                << ")\">" << EscapeHtml(WStringToUtf8(attributes[i])) << "</th>\n";
        }

        file << R"(                            </tr>
                        </thead>
                        <tbody id="tableBody">
)";

        for (size_t i=0; i < entries.size(); ++i)
        {
            const auto& e=entries[i];
            file << "                            <tr>\n";
            file << "                                <td>" << (i + 1) << "</td>\n";

            for (const auto& attr : attributes)
            {
                std::wstring joined;
                auto it=e.attrs.find(attr);
                if (it != e.attrs.end() && !it->second.empty())
                {
                    for (size_t k=0; k < it->second.size(); ++k)
                    {
                        if (k > 0) joined += L" | ";
                        joined += it->second[k];
                    }
                }

                std::string cellValue=EscapeHtml(WStringToUtf8(joined));
                std::string title=cellValue.length() > 50 ? " title=\"" + cellValue + "\"" : "";

                file << "                                <td" << title << ">" << cellValue << "</td>\n";
            }

            file << "                            </tr>\n";
        }

        file << R"(                        </tbody>
                    </table>
                </div>
                <div class="pagination" id="pagination"></div>
            </div>
        </div>
    </div>

    <!-- Statistics Modal -->
    <div class="modal" id="statsModal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal('statsModal')\">&times;</span>
            <h2>📊 Advanced Statistics & Analytics</h2>

            <div class="stats-tabs">
                <div class="stats-tab active" onclick="switchStatsTab('overview')\">📈 Overview</div>
                <div class="stats-tab" onclick="switchStatsTab('columns')\>📋 Column Details</div>
                <div class="stats-tab" onclick="switchStatsTab('charts')\">📊 Charts</div>
                <div class="stats-tab" onclick="switchStatsTab('custom')\">⚙️ Custom Stats</div>
            </div>

            <div id="statsOverview" class="stats-content active"></div>
            <div id="statsColumns" class="stats-content"></div>
            <div id="statsCharts" class="stats-content"></div>
            <div id="statsCustom" class="stats-content">
                <div class="custom-stats-builder">
                    <h3>🔧 Custom Statistics Builder</h3>
                    <div class="builder-row">
                        <span class="builder-label">Column:</span>
                        <select id="customStatsColumn" class="select-box">
)";

            for (const auto& attr : attributes)
            {
                file << "                            <option value=\"" << EscapeHtml(WStringToUtf8(attr))
                    << "\">" << EscapeHtml(WStringToUtf8(attr)) << "</option>\n";
            }

            file << R"(                        </select>
                    </div>
                    <div class="builder-row">
                        <span class="builder-label">Operation:</span>
                        <select id="customStatsOperation" class="select-box">
                            <option value="count">Count</option>
                            <option value="unique">Unique Values</option>
                            <option value="frequency">Frequency Distribution</option>
                            <option value="sum">Sum (numeric)</option>
                            <option value="avg">Average (numeric)</option>
                            <option value="min">Minimum</option>
                            <option value="max">Maximum</option>
                            <option value="median">Median (numeric)</option>
                            <option value="mode">Mode (most common)</option>
                            <option value="stddev">Standard Deviation</option>
                            <option value="percentile">Percentile</option>
                        </select>
                    </div>
                    <div class="builder-row" id="percentileInput" style="display: none;">
                        <span class="builder-label">Percentile:</span>
                        <input type="number" id="percentileValue" min="0" max="100" value="50" class="search-box" style="max-width: 100px;">
                    </div>
                    <div class="builder-row">
                        <span class="builder-label">Filter:</span>
                        <div id="customStatsFilters"></div>
                        <button class="btn" onclick="addCustomFilter()\">➕ Add Filter</button>
                    </div>
                    <div class="builder-row">
                        <button class="btn btn-success" onclick="calculateCustomStats()\">🔬 Calculate</button>
                        <button class="btn btn-secondary" onclick="clearCustomStats()\">🗑️ Clear</button>
                    </div>
                </div>
                <div id="customStatsResult" class="stats-result" style="display: none;"></div>
            </div>
        </div>
    </div>

    <script>
        let allData=[];
        let filteredData=[];
        let currentPage=1;
        let rowsPerPage=100;
        let sortColumn=-1;
        let sortAsc=true;
        let currentSearchMode='basic';
        const headers=[)\";

        for (size_t i=0; i < attributes.size(); ++i)
        {
            if (i > 0) file << ", ";
            file << "\"" << EscapeJson(WStringToUtf8(attributes[i])) << "\"";
        }

        file << R"(];

        // Parse table data
        function parseTableData() {
            const tbody=document.getElementById('tableBody');
            const rows=tbody.querySelectorAll('tr');
            
            rows.forEach((row, idx) => {
                const cells=row.querySelectorAll('td');
                const rowData={};
                
                headers.forEach((header, i) => {
                    rowData[header]=cells[i + 1].textContent.trim();
                });
                
                allData.push(rowData);
            });
            
            filteredData=[...allData];
        }

        parseTableData();

        const searchBox=document.getElementById('searchBox');
        const columnFilter=document.getElementById('columnFilter');
        const searchType=document.getElementById('searchType');
        const caseSensitive=document.getElementById('caseSensitive');
        const rowsPerPageSelect=document.getElementById('rowsPerPage');

        searchBox.addEventListener('input', filterTable);
        columnFilter.addEventListener('change', filterTable);
        searchType.addEventListener('change', filterTable);
        caseSensitive.addEventListener('change', filterTable);
        rowsPerPageSelect.addEventListener('change', (e) => {
            rowsPerPage=parseInt(e.target.value);
            currentPage=1;
            renderTable();
        });

        // Search Mode Toggle
        function toggleSearchMode(mode) {
            currentSearchMode=mode;
            const modeBtns=document.querySelectorAll('.mode-btn');
            modeBtns.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            document.getElementById('basicSearch').style.display=mode === 'basic' ? 'flex' : 'none';
            document.getElementById('advancedSearch').classList.toggle('active', mode === 'advanced' || mode === 'regex');
            
            if (mode === 'regex') {
                searchBox.placeholder='🔧 Enter regex pattern...';
            } else {
                searchBox.placeholder='🔍 Quick search...';
            }
        }

        // Advanced Search
        function addCondition() {
            const container=document.getElementById('searchConditions');
            const firstCondition=container.querySelector('.search-condition');
            const newCondition=firstCondition.cloneNode(true);
            newCondition.querySelector('input').value='';
            newCondition.querySelector('.remove-condition').style.display='inline-block';
            container.appendChild(newCondition);
        }

        function removeCondition(btn) {
            btn.closest('.search-condition').remove();
        }

        function applyAdvancedSearch() {
            const conditions=Array.from(document.querySelectorAll('.search-condition')).map(cond => ({
                column: cond.querySelector('.condition-column').value,
                operator: cond.querySelectorAll('.search-operator')[0].value,
                value: cond.querySelector('input').value,
                logic: cond.querySelectorAll('.search-operator')[1].value
            }));

            filteredData=allData.filter(row => {
                let result=true;
                let lastLogic='AND';

                for (let i=0; i < conditions.length; i++) {
                    const cond=conditions[i];
                    if (!cond.column || !cond.value) continue;

                    const cellValue=String(row[cond.column] || '').toLowerCase();
                    const searchValue=cond.value.toLowerCase();
                    let condResult=false;

                    switch (cond.operator) {
                        case 'contains': condResult=cellValue.includes(searchValue); break;
                        case 'equals': condResult=cellValue === searchValue; break;
                        case 'startsWith': condResult=cellValue.startsWith(searchValue); break;
                        case 'endsWith': condResult=cellValue.endsWith(searchValue); break;
                        case 'notContains': condResult=!cellValue.includes(searchValue); break;
                        case 'gt': condResult=parseFloat(cellValue) > parseFloat(searchValue); break;
                        case 'lt': condResult=parseFloat(cellValue) < parseFloat(searchValue); break;
                        case 'gte': condResult=parseFloat(cellValue) >= parseFloat(searchValue); break;
                        case 'lte': condResult=parseFloat(cellValue) <= parseFloat(searchValue); break;
                    }

                    if (i === 0) {
                        result=condResult;
                    } else {
                        if (lastLogic === 'AND') {
                            result=result && condResult;
                        } else {
                            result=result || condResult;
                        }
                    }

                    lastLogic=cond.logic;
                }

                return result;
            });

            currentPage=1;
            updateStats();
            renderTable();
        }

        // Basic Filter
        function filterTable() {
            if (currentSearchMode !== 'basic') return;

            const searchTerm=caseSensitive.checked ? searchBox.value : searchBox.value.toLowerCase();
            const column=columnFilter.value;
            const type=searchType.value;

            if (!searchTerm) {
                filteredData=[...allData];
            } else {
                filteredData=allData.filter(row => {
                    const checkValue=(val) => {
                        const cellValue=caseSensitive.checked ? String(val) : String(val).toLowerCase();
                        
                        if (currentSearchMode === 'regex') {
                            try {
                                const regex=new RegExp(searchTerm, caseSensitive.checked ? '' : 'i');
                                return regex.test(cellValue);
                            } catch (e) {
                                return false;
                            }
                        }

                        switch (type) {
                            case 'contains': return cellValue.includes(searchTerm);
                            case 'equals': return cellValue === searchTerm;
                            case 'startsWith': return cellValue.startsWith(searchTerm);
                            case 'endsWith': return cellValue.endsWith(searchTerm);
                            case 'notContains': return !cellValue.includes(searchTerm);
                            default: return cellValue.includes(searchTerm);
                        }
                    };

                    if (column) {
                        return checkValue(row[column] || '');
                    } else {
                        return headers.some(header => checkValue(row[header] || ''));
                    }
                });
            }

            currentPage=1;
            updateStats();
            renderTable();
        }

        function updateStats() {
            document.getElementById('displayedRows').textContent=filteredData.length.toLocaleString();
            document.getElementById('headerTotalEntries').textContent=filteredData.length.toLocaleString();
            document.getElementById('currentPageDisplay').textContent=currentPage;
        }

        function renderTable() {
            const start=rowsPerPage === -1 ? 0 : (currentPage - 1) * rowsPerPage;
            const end=rowsPerPage === -1 ? filteredData.length : start + rowsPerPage;
            const pageData=filteredData.slice(start, end);

            const tbody=document.getElementById('tableBody');
            const searchTerm=searchBox.value.toLowerCase();

            if (pageData.length === 0) {
                tbody.innerHTML=`
                    <tr><td colspan="${headers.length + 1}">
                        <div class="empty-state">
                            <div class="empty-state-icon">🔍</div>
                            <h2>No results found</h2>
                            <p>Try adjusting your search criteria</p>
                        </div>
                    </td></tr>
                `;
            } else {
                let html='';
                const startIdx=rowsPerPage === -1 ? 0 : (currentPage - 1) * rowsPerPage;
                
                pageData.forEach((row, idx) => {
                    html += '<tr>';
                    html += `<td>${startIdx + idx + 1}</td>`;
                    
                    headers.forEach(header => {
                        let value=row[header] || '';
                        let displayValue=value;

                        if (searchTerm && currentSearchMode === 'basic' && displayValue.toLowerCase().includes(searchTerm)) {
                            const regex=new RegExp(`(${searchTerm})`, 'gi');
                            displayValue=displayValue.replace(regex, '<span class="highlight">$1</span>');
                        }

                        const title=value.length > 50 ? ` title="${value}"` : '';
                        html += `<td${title}>${displayValue}</td>`;
                    });
                    
                    html += '</tr>';
                });
                
                tbody.innerHTML=html;
            }

            renderPagination();
            updateStats();
        }

        function renderPagination() {
            const paginationDiv=document.getElementById('pagination');
            
            if (rowsPerPage === -1 || filteredData.length === 0) {
                paginationDiv.innerHTML='';
                return;
            }

            const totalPages=Math.ceil(filteredData.length / rowsPerPage);
            let html='';

            html += `<button class="page-btn" onclick="changePage(${currentPage - 1})\" ${ currentPage ===1 ? 'disabled' : '' } > ◀ Prev</button>`;

            const startPage=Math.max(1, currentPage - 2);
            const endPage=Math.min(totalPages, currentPage + 2);

            if (startPage > 1) {
                html += `<button class="page-btn" onclick="changePage(1)\" > 1 </button>`;
                    if (startPage > 2) html += `<span style="padding: 0 10px;" > ...</span>`;
            }

            for (let i=startPage; i <= endPage; i++) {
                html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})\" > ${ i }</button>`;
            }

            if (endPage < totalPages) {
                if (endPage < totalPages - 1) html += `<span style="padding: 0 10px;" > ...</span>`;
                    html += `<button class="page-btn" onclick="changePage(${totalPages})\" > ${ totalPages }</button>`;
            }

            html += `<button class="page-btn" onclick="changePage(${currentPage + 1})\" ${ currentPage ===totalPages ? 'disabled' : '' } > Next ▶</button>`;
            html += `<span style="margin-left: 20px; color: #666;" > Page ${ currentPage } / ${ totalPages }</span>`;

            paginationDiv.innerHTML=html;
        }

        function changePage(page) {
            const totalPages=Math.ceil(filteredData.length / rowsPerPage);
            if (page < 1 || page > totalPages) return;
            currentPage=page;
            renderTable();
            document.querySelector('.table-wrapper').scrollTop=0;
        }

        function sortTable(colIdx) {
            if (sortColumn === colIdx) {
                sortAsc=!sortAsc;
            } else {
                sortColumn=colIdx;
                sortAsc=true;
            }

            const header=headers[colIdx];
            const thElements=document.querySelectorAll('th.sortable');
            
            thElements.forEach((th, idx) => {
                th.classList.remove('sorted-asc', 'sorted-desc');
                if (idx === colIdx) {
                    th.classList.add(sortAsc ? 'sorted-asc' : 'sorted-desc');
                }
            });

            filteredData.sort((a, b) => {
                let valA=a[header] || '';
                let valB=b[header] || '';

                const numA=parseFloat(valA);
                const numB=parseFloat(valB);
                
                if (!isNaN(numA) && !isNaN(numB)) {
                    return sortAsc ? numA - numB : numB - numA;
                }

                const strA=String(valA).toLowerCase();
                const strB=String(valB).toLowerCase();

                if (sortAsc) {
                    return strA.localeCompare(strB);
                } else {
                    return strB.localeCompare(strA);
                }
            });

            currentPage=1;
            renderTable();
        }

        function clearFilter() {
            searchBox.value='';
            columnFilter.value='';
            searchType.value='contains';
            caseSensitive.checked=false;
            filteredData=[...allData];
            currentPage=1;
            
            const thElements=document.querySelectorAll('th.sortable');
            thElements.forEach(th => {
                th.classList.remove('sorted-asc', 'sorted-desc');
            });
            sortColumn=-1;
            sortAsc=true;
            
            const advConditions=document.getElementById('searchConditions');)";
            file << R"(const conditions=advConditions.querySelectorAll('.search-condition');)";
            file << R"(conditions.forEach((cond, idx) => {
                if (idx > 0) cond.remove();
                else {
                    cond.querySelector('.condition-column').value='';
                    cond.querySelector('input').value='';
                }
            });
            
            renderTable();
        }

        // Statistics Functions
        function showStatistics() {
            generateOverviewStats();
            generateColumnStats();
            document.getElementById('statsModal').style.display='block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display='none';
        }

        function switchStatsTab(tab) {
            document.querySelectorAll('.stats-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.stats-content').forEach(c => c.classList.remove('active'));
            
            event.target.classList.add('active');
            
            switch(tab) {
                case 'overview':
                    document.getElementById('statsOverview').classList.add('active');
                    break;
                case 'columns':
                    document.getElementById('statsColumns').classList.add('active');
                    break;
                case 'charts':
                    document.getElementById('statsCharts').classList.add('active');
                    generateCharts();
                    break;
                case 'custom':
                    document.getElementById('statsCustom').classList.add('active');
                    break;
            }
        }

        function generateOverviewStats() {
            const container=document.getElementById('statsOverview');
            
            let totalCells=allData.length * headers.length;
            let filledCells=0;
            let emptyCells=0;
            let duplicateRows=0;
            
            const rowStrings=new Set();
            allData.forEach(row => {
                const rowStr=headers.map(h => row[h]).join('|');
                if (rowStrings.has(rowStr)) duplicateRows++;
                rowStrings.add(rowStr);
                
                headers.forEach(h => {
                    if (row[h] && row[h].trim() !== '') filledCells++;
                    else emptyCells++;
                });
            });
            
            const fillRate=((filledCells / totalCells) * 100).toFixed(2);
            
            let html=`
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                    <div class="stat-card">
                        <div class="stat-label">Total Rows</div>
                        <div class="stat-value">${allData.length.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total Columns</div>
                        <div class="stat-value">${headers.length}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total Cells</div>
                        <div class="stat-value">${totalCells.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Filled Cells</div>
                        <div class="stat-value">${filledCells.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Empty Cells</div>
                        <div class="stat-value">${emptyCells.toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Data Fill Rate</div>
                        <div class="stat-value">${fillRate}%</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Duplicate Rows</div>
                        <div class="stat-value">${duplicateRows}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Unique Rows</div>
                        <div class="stat-value">${(allData.length - duplicateRows).toLocaleString()}</div>
                    </div>
                </div>
            `;
            
            container.innerHTML=html;
        }

        function generateColumnStats() {
            const container=document.getElementById('statsColumns');
            let html='';

            headers.forEach(header => {
                const values=allData.map(row => row[header]).filter(v => v !== null && v !== undefined && v !== '');
                const uniqueValues=[...new Set(values)];
                const numericValues=values.filter(v => !isNaN(parseFloat(v))).map(v => parseFloat(v));
                const isNumeric=numericValues.length > values.length * 0.5 && numericValues.length > 0;

                html += `<div class="column-stats">`;
                html += `<h4>📊 ${header}</h4>`;
                html += `<div class="stat-row"><span>Total values:</span><strong>${values.length.toLocaleString()}</strong></div>`;
                html += `<div class="stat-row"><span>Unique values:</span><strong>${uniqueValues.length.toLocaleString()}</strong></div>`;
                html += `<div class="stat-row"><span>Empty values:</span><strong>${(allData.length - values.length).toLocaleString()}</strong></div>`;
                html += `<div class="stat-row"><span>Fill rate:</span><strong>${((values.length / allData.length) * 100).toFixed(2)}%</strong></div>`;

                if (isNumeric) {
                    const sum=numericValues.reduce((a, b) => a + b, 0);
                    const avg=sum / numericValues.length;
                    const min=Math.min(...numericValues);
                    const max=Math.max(...numericValues);
                    const sorted=[...numericValues].sort((a, b) => a - b);
                    const median=sorted[Math.floor(sorted.length / 2)];
                    const variance=numericValues.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / numericValues.length;
                    const stdDev=Math.sqrt(variance);
                    const q1=sorted[Math.floor(sorted.length * 0.25)];
                    const q3=sorted[Math.floor(sorted.length * 0.75)];

                    html += `<div class="stat-row"><span>Data type:</span><strong>Numeric</strong></div>`;
                    html += `<div class="stat-row"><span>Min:</span><strong>${min.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Max:</span><strong>${max.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Average:</span><strong>${avg.toFixed(2)}</strong></div>`;
                    html += `<div class="stat-row"><span>Median:</span><strong>${median.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Sum:</span><strong>${sum.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Std Deviation:</span><strong>${stdDev.toFixed(2)}</strong></div>`;
                    html += `<div class="stat-row"><span>Q1 (25%):</span><strong>${q1.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Q3 (75%):</span><strong>${q3.toLocaleString()}</strong></div>`;
                    html += `<div class="stat-row"><span>Range:</span><strong>${(max - min).toLocaleString()}</strong></div>`;
                } else {
                    const avgLength=values.reduce((acc, val) => acc + String(val).length, 0) / values.length;
                    const minLength=Math.min(...values.map(v => String(v).length));
                    const maxLength=Math.max(...values.map(v => String(v).length));

                    html += `<div class="stat-row"><span>Data type:</span><strong>Text</strong></div>`;
                    html += `<div class="stat-row"><span>Avg length:</span><strong>${avgLength.toFixed(2)} chars</strong></div>`;
                    html += `<div class="stat-row"><span>Min length:</span><strong>${minLength} chars</strong></div>`;
                    html += `<div class="stat-row"><span>Max length:</span><strong>${maxLength} chars</strong></div>`;
                }

                if (uniqueValues.length > 0 && uniqueValues.length <= 100) {
                    const frequency={};
                    values.forEach(v => {
                        frequency[v]=(frequency[v] || 0) + 1;
                    });
                    const sorted=Object.entries(frequency).sort((a, b) => b[1] - a[1]);
                    const top10=sorted.slice(0, 10);

                    html += `<div class="stat-row"><span>Top 10 most common:</span><strong></strong></div>`;
                    top10.forEach(([val, count], idx) => {
                        const percentage=((count / values.length) * 100).toFixed(1);
                        const displayVal=val.length > 40 ? val.substring(0, 40) + '...' : val;
                        html += `<div class="stat-row" style="padding-left: 20px;"><span>${idx + 1}. ${displayVal}</span><strong>${count} (${percentage}%)</strong></div>`;
                    });
                }

                html += `</div>`;
            });

            container.innerHTML=html;
        }

        function generateCharts() {
            const container=document.getElementById('statsCharts');
            let html='';
            
            headers.slice(0, 6).forEach((header, idx) => {
                const values=allData.map(row => row[header]).filter(v => v !== null && v !== undefined && v !== '');
                const uniqueValues=[...new Set(values)];
                
                if (uniqueValues.length <= 20) {
                    const frequency={};
                    values.forEach(v => {
                        frequency[v]=(frequency[v] || 0) + 1;
                    });
                    const sorted=Object.entries(frequency).sort((a, b) => b[1] - a[1]).slice(0, 10);
                    
                    html += `
                        <div class="chart-container">
                            <h3>${header} - Distribution</h3>
                            <canvas id="chart${idx}"></canvas>
                        </div>
                    `;
                }
            });
            
            container.innerHTML=html;
            
            setTimeout(() => {
                headers.slice(0, 6).forEach((header, idx) => {
                    const canvas=document.getElementById('chart' + idx);
                    if (!canvas) return;
                    
                    const values=allData.map(row => row[header]).filter(v => v !== null && v !== undefined && v !== '');
                    const uniqueValues=[...new Set(values)];
                    
                    if (uniqueValues.length <= 20) {
                        const frequency={};
                        values.forEach(v => {
                            frequency[v]=(frequency[v] || 0) + 1;
                        });
                        const sorted=Object.entries(frequency).sort((a, b) => b[1] - a[1]).slice(0, 10);
                        
                        new Chart(canvas, {
                            type: 'bar',
                            data: {
                                labels: sorted.map(([val]) => val.length > 20 ? val.substring(0, 20) + '...' : val),
                                datasets: [{
                                    label: 'Frequency',
                                    data: sorted.map(([_, count]) => count),
                                    backgroundColor: 'rgba(102, 126, 234, 0.7)',
                                    borderColor: 'rgba(102, 126, 234, 1)',
                                    borderWidth: 2
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: true,
                                plugins: {
                                    legend: { display: false }
                                },
                                scales: {
                                    y: { beginAtZero: true }
                                }
                            }
                        });
                    }
                });
            }, 100);
        }

        // Custom Statistics
        document.getElementById('customStatsOperation').addEventListener('change', function() {
            document.getElementById('percentileInput').style.display=this.value === 'percentile' ? 'flex' : 'none';
        });

        function addCustomFilter() {
            const container=document.getElementById('customStatsFilters');
            const filterHtml=`
                <div class="condition-group" style="display: flex; gap: 10px; margin-top: 10px;">
                    <select class="select-box">
                        ${headers.map(h => `<option value="${h}">${h}</option>`).join('')}
                    </select>
                    <select class="select-box">
                        <option value="equals">Equals</option>
                        <option value="contains">Contains</option>
                        <option value="gt">Greater than</option>
                        <option value="lt">Less than</option>
                    </select>
                    <input type="text" class="search-box" placeholder="Value" style="flex: 1;">
                    <button class="remove-condition" onclick="this.parentElement.remove()\" >✖</button>
                </div>
            `;
            container.insertAdjacentHTML('beforeend', filterHtml);
        }

        function calculateCustomStats() {
            const column=document.getElementById('customStatsColumn').value;
            const operation=document.getElementById('customStatsOperation').value;
            const percentileVal=parseInt(document.getElementById('percentileValue').value);
            
            const filters=Array.from(document.getElementById('customStatsFilters').querySelectorAll('.condition-group')).map(group => ({
                column: group.querySelector('.select-box').value,
                operator: group.querySelectorAll('.select-box')[1].value,
                value: group.querySelector('input').value
            }));
            
            let data=[...allData];
            
            filters.forEach(filter => {
                if (!filter.value) return;
                data=data.filter(row => {
                    const cellValue=String(row[filter.column] || '').toLowerCase();
                    const filterValue=filter.value.toLowerCase();
                    
                    switch(filter.operator) {
                        case 'equals': return cellValue === filterValue;
                        case 'contains': return cellValue.includes(filterValue);
                        case 'gt': return parseFloat(cellValue) > parseFloat(filterValue);
                        case 'lt': return parseFloat(cellValue) < parseFloat(filterValue);
                        default: return true;
                    }
                });
            });
            
            const values=data.map(row => row[column]).filter(v => v !== null && v !== undefined && v !== '');
            const numericValues=values.filter(v => !isNaN(parseFloat(v))).map(v => parseFloat(v));
            
            let result='';
            
            switch(operation) {
                case 'count':
                    result=`Count: ${values.length.toLocaleString()}`;
                    break;
                case 'unique':
                    const unique=[...new Set(values)];
                    result=`Unique values: ${unique.length.toLocaleString()}`;
                    break;
                case 'frequency':
                    const freq={};
                    values.forEach(v => freq[v]=(freq[v] || 0) + 1);)";
                    file << R"(const sorted=Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 20);
                    result='<table style="width: 100%; border-collapse: collapse;"><tr><th style="border: 1px solid #ddd; padding: 8px;">Value</th><th style="border: 1px solid #ddd; padding: 8px;">Count</th><th style="border: 1px solid #ddd; padding: 8px;">Percentage</th></tr>';
                    sorted.forEach(([val, count]) => {
                        const pct=((count / values.length) * 100).toFixed(2);
                        result += `<tr><td style="border: 1px solid #ddd; padding: 8px;">${val}</td><td style="border: 1px solid #ddd; padding: 8px;">${count}</td><td style="border: 1px solid #ddd; padding: 8px;">${pct}%</td></tr>`;
                    });
                    result += '</table>';
                    break;
                case 'sum':
                    result=`Sum: ${numericValues.reduce((a, b) => a + b, 0).toLocaleString()}`;
                    break;
                case 'avg':
                    result=`Average: ${(numericValues.reduce((a, b) => a + b, 0) / numericValues.length).toFixed(2)}`;
                    break;
                case 'min':
                    result=`Minimum: ${Math.min(...numericValues).toLocaleString()}`;
                    break;
                case 'max':
                    result=`Maximum: ${Math.max(...numericValues).toLocaleString()}`;
                    break;
                case 'median':
                    const sorted2=[...numericValues].sort((a, b) => a - b);
                    result=`Median: ${sorted2[Math.floor(sorted2.length / 2)].toLocaleString()}`;
                    break;
                case 'mode':
                    const freq2={};
                    values.forEach(v => freq2[v]=(freq2[v] || 0) + 1);
                    const mode=Object.entries(freq2).sort((a, b) => b[1] - a[1])[0];
                    result=`Mode: ${mode[0]} (appears ${mode[1]} times)`;
                    break;
                case 'stddev':
                    const avg=numericValues.reduce((a, b) => a + b, 0) / numericValues.length;
                    const variance=numericValues.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / numericValues.length;
                    result=`Standard Deviation: ${Math.sqrt(variance).toFixed(2)}`;
                    break;
                case 'percentile':
                    const sorted3=[...numericValues].sort((a, b) => a - b);
                    const idx=Math.floor((percentileVal / 100) * sorted3.length);
                    result=`${percentileVal}th Percentile: ${sorted3[idx].toLocaleString()}`;
                    break;
            }
            
            const resultDiv=document.getElementById('customStatsResult');
            resultDiv.innerHTML=`
                <h4>📊 Result</h4>
                <p><strong>Column:</strong> ${column}</p>
                <p><strong>Operation:</strong> ${operation}</p>
                <p><strong>Filtered rows:</strong> ${data.length.toLocaleString()} / ${allData.length.toLocaleString()}</p>
                <hr style="margin: 15px 0;">
                <div style="font-size: 16px;">${result}</div>
            `;
            resultDiv.style.display='block';
        }

        function clearCustomStats() {
            document.getElementById('customStatsFilters').innerHTML='';
            document.getElementById('customStatsResult').style.display='none';
        }

        // Export Functions
        function exportFilteredCSV() {
            if (filteredData.length === 0) {
                alert('❌ No data to export!');
                return;
            }

            let csv=headers.join(',') + '\\n';

            filteredData.forEach(row => {
                const rowData=headers.map(header => {
                    let value=row[header] || '';
                    value=String(value);
                    if (value.includes(',') || value.includes('"') || value.includes('\\n')) {
                        value='"' + value.replace(/"/g, '""') + '"';
                    }
                    return value;
                });
                csv += rowData.join(',') + '\\n';
            });

            downloadFile(csv, 'ldap_filtered_results.csv', 'text/csv;charset=utf-8;');
        }

        function exportFilteredJSON() {
            if (filteredData.length === 0) {
                alert('❌ No data to export!');
                return;
            }

            const json=JSON.stringify(filteredData, null, 2);
            downloadFile(json, 'ldap_filtered_results.json', 'application/json');
        }

        function downloadFile(content, filename, mimeType) {
            const BOM='\\uFEFF';
            const blob=new Blob([BOM + content], { type: mimeType });
            const url=URL.createObjectURL(blob);
            const a=document.createElement('a');
            a.href=url;
            a.download=filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            alert('✅ File exported successfully!');
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                if (e.key === 'f') {
                    e.preventDefault();
                    searchBox.focus();
                } else if (e.key === 's') {
                    e.preventDefault();
                    exportFilteredCSV();
                } else if (e.key === 'r') {
                    e.preventDefault();
                    clearFilter();
                }
            } else if (e.key === 'Escape') {
                document.querySelectorAll('.modal').forEach(m => m.style.display='none');
            }
        });

        // Close modal on outside click
        window.onclick=function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display='none';
            }
        }

        // Initial render
        renderTable();
    </script>
</body>
</html>)";

                    file.close();
    }

    class LDAPConnection
    {
    private:
        LDAP* ldapConnection;

    public:
        LDAPConnection(const std::wstring& serverAddress, ULONG port=LDAP_PORT)
            : ldapConnection(ldap_initW(const_cast<PWSTR>(serverAddress.c_str()), port))
        {
            if (ldapConnection == NULL)
            {
                std::cerr << "Khởi tạo LDAP thất bại. Mã lỗi: " << LdapGetLastError() << std::endl;
            }
        }

        ~LDAPConnection()
        {
            Disconnect();
        }

        bool Connect(const std::wstring& username, const std::wstring& password, const std::wstring& domain)
        {
            if (ldapConnection == NULL)
                return false;

            ULONG version=LDAP_VERSION3;
            ULONG returnCode=ldap_set_option(ldapConnection, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
            if (returnCode != LDAP_SUCCESS)
            {
                std::cerr << "Không thể đặt phiên bản giao thức LDAP: " << ldap_err2stringA(returnCode) << std::endl;
                return false;
            }

            SEC_WINNT_AUTH_IDENTITY_W authIdent={};
            authIdent.User=(unsigned short*)username.c_str();
            authIdent.UserLength=static_cast<unsigned long>(username.length());
            authIdent.Password=(unsigned short*)password.c_str();
            authIdent.PasswordLength=static_cast<unsigned long>(password.length());
            authIdent.Domain=(unsigned short*)domain.c_str();
            authIdent.DomainLength=static_cast<unsigned long>(domain.length());
            authIdent.Flags=SEC_WINNT_AUTH_IDENTITY_UNICODE;

            returnCode=ldap_bind_sW(ldapConnection, NULL, (PWCHAR)&authIdent, LDAP_AUTH_NEGOTIATE);
            if (returnCode != LDAP_SUCCESS)
            {
                std::cerr << "Kết nối LDAP thất bại. Mã lỗi: " << ldap_err2stringA(returnCode) << std::endl;
                return false;
            }
            return true;
        }

        void Disconnect()
        {
            if (ldapConnection != NULL)
            {
                ldap_unbind(ldapConnection);
                ldapConnection=NULL;
            }
        }

        void Search(const std::wstring& baseDN, const std::wstring& filter,
            const std::vector<std::wstring>& attributes, ULONG scope, ULONG sizeLimit,
            OutputFormat format, const std::wstring& outputFile)
        {
            if (ldapConnection == NULL)
            {
                std::cerr << "Chưa kết nối với LDAP." << std::endl;
                return;
            }

            bool collectForExport=(format != OutputFormat::CONSOLE_ONLY && !outputFile.empty());
            bool isWildcard=!attributes.empty() && attributes[0] == L"*";
            std::vector<Entry> entries;
            std::set<std::wstring> allAttributes;

            LDAPMessage* pSearchResult=NULL;
            std::vector<PWCHAR> attrList;
            if (!isWildcard)
            {
                for (const auto& attr : attributes)
                    attrList.push_back(const_cast<PWSTR>(attr.c_str()));
                attrList.push_back(NULL);
            }

            struct l_timeval timeout { 1000, 0 };
            ULONG pageSize=1000;
            LDAPControlW pageControl{ const_cast<wchar_t*>(L"1.2.840.113556.1.4.319"), {0}, FALSE };
            LDAPControlW* serverControls[]={ &pageControl, NULL };
            LDAPControlW* clientControls[]={ NULL };
            struct berval cookie={ 0, NULL };
            bool morePages=true;
            int totalEntries=0;

            std::wcout << L"***Searching..." << std::endl;

            while (morePages)
            {
                struct berval pageSizeBerval { static_cast<int>(sizeof(ULONG)), reinterpret_cast<char*>(&pageSize) };
                pageControl.ldctl_value=pageSizeBerval;

                ULONG returnCode=ldap_search_ext_sW(
                    ldapConnection,
                    const_cast<PWSTR>(baseDN.c_str()),
                    scope,
                    const_cast<PWSTR>(filter.c_str()),
                    isWildcard ? NULL : attrList.data(),
                    0,
                    serverControls,
                    clientControls,
                    &timeout,
                    sizeLimit,
                    &pSearchResult);

                if (returnCode != LDAP_SUCCESS && returnCode != LDAP_SIZELIMIT_EXCEEDED)
                {
                    std::wcerr << L"Lỗi tìm kiếm LDAP. Mã lỗi: " << returnCode << std::endl;
                    if (pSearchResult) ldap_msgfree(pSearchResult);
                    if (cookie.bv_val) free(cookie.bv_val);
                    return;
                }

                int entryCount=ldap_count_entries(ldapConnection, pSearchResult);
                totalEntries += entryCount;
                std::wcout << L"Found " << entryCount << L" entries (Total: " << totalEntries << L")" << std::endl;

                if (entryCount == 0)
                {
                    ldap_msgfree(pSearchResult);
                    if (cookie.bv_val) free(cookie.bv_val);
                    break;
                }

                LDAPMessage* pEntry=ldap_first_entry(ldapConnection, pSearchResult);
                while (pEntry != NULL)
                {
                    PWCHAR dn=ldap_get_dnW(ldapConnection, pEntry);
                    std::wstring dn_str=dn ? dn : L"";
                    ldap_memfree(dn);

                    Entry e;
                    e.dn=dn_str;

                    BerElement* pBer=NULL;
                    PWCHAR attribute=ldap_first_attributeW(ldapConnection, pEntry, &pBer);
                    while (attribute != NULL)
                    {
                        if (collectForExport)
                        {
                            allAttributes.insert(attribute);
                        }

                        PWCHAR* vals=ldap_get_valuesW(ldapConnection, pEntry, attribute);
                        struct berval** bvals=ldap_get_values_lenW(ldapConnection, pEntry, attribute);
                        int valCount=vals ? ldap_count_valuesW(vals) : 0;

                        std::vector<std::wstring> fvals;
                        for (int i=0; i < valCount; ++i)
                        {
                            std::wstring fval=FormatAttributeValue(std::wstring(attribute), vals[i], bvals && bvals[i] ? bvals[i] : nullptr);
                            fvals.push_back(fval);
                        }

                        if (!fvals.empty())
                        {
                            e.attrs[attribute]=std::move(fvals);
                        }

                        if (vals) ldap_value_freeW(vals);
                        if (bvals) ldap_value_free_len(bvals);
                        ldap_memfree(attribute);
                        attribute=ldap_next_attributeW(ldapConnection, pEntry, pBer);
                    }
                    if (pBer) ber_free(pBer, 0);

                    if (collectForExport)
                    {
                        entries.push_back(std::move(e));
                    }

                    pEntry=ldap_next_entry(ldapConnection, pEntry);
                }

                LDAPControlW** returnedControls=NULL;
                if (ldap_parse_resultW(ldapConnection, pSearchResult, NULL, NULL, NULL, NULL, &returnedControls, FALSE) == LDAP_SUCCESS)
                {
                    for (ULONG i=0; returnedControls && returnedControls[i]; ++i)
                    {
                        if (wcscmp(returnedControls[i]->ldctl_oid, L"1.2.840.113556.1.4.319") == 0)
                        {
                            cookie.bv_len=returnedControls[i]->ldctl_value.bv_len;
                            if (cookie.bv_len > 0)
                            {
                                cookie.bv_val=(char*)malloc(cookie.bv_len);
                                if (cookie.bv_val)
                                    memcpy(cookie.bv_val, returnedControls[i]->ldctl_value.bv_val, cookie.bv_len);
                                else
                                    morePages=false;
                            }
                            else
                            {
                                morePages=false;
                            }
                            break;
                        }
                    }
                    ldap_controls_freeW(returnedControls);
                }

                ldap_msgfree(pSearchResult);
                pSearchResult=NULL;

                if (cookie.bv_val)
                {
                    pageControl.ldctl_value=cookie;
                }
                else
                {
                    morePages=false;
                }
            }

            if (cookie.bv_val) free(cookie.bv_val);

            std::wcout << L"\nTotal entries found: " << totalEntries << std::endl;

            if (collectForExport && !entries.empty())
            {
                std::vector<std::wstring> exportAttributes=isWildcard ? std::vector<std::wstring>(allAttributes.begin(), allAttributes.end()) : attributes;

                std::wcout << L"\n*** Exporting results..." << std::endl;

                switch (format)
                {
                case OutputFormat::CSV:
                    std::wcout << L"Format: CSV" << std::endl;
                    WriteCsvFile(outputFile, exportAttributes, entries);
                    break;
                case OutputFormat::TXT:
                    std::wcout << L"Format: TXT" << std::endl;
                    WriteTxtFile(outputFile, entries);
                    break;
                case OutputFormat::JSON:
                    std::wcout << L"Format: JSON" << std::endl;
                    WriteJsonFile(outputFile, entries);
                    break;
                case OutputFormat::XML:
                    std::wcout << L"Format: XML" << std::endl;
                    WriteXmlFile(outputFile, entries);
                    break;
                case OutputFormat::HTML:
                    std::wcout << L"Format: HTML Advanced Viewer" << std::endl;
                    WriteHtmlFile(outputFile, exportAttributes, entries);
                    break;
                default:
                    break;
                }

                std::wcout << L"✓ Export successful: " << outputFile << std::endl;
                std::wcout << L"  Total entries: " << entries.size() << std::endl;
                std::wcout << L"  Total attributes: " << exportAttributes.size() << std::endl;
            }
        }
    };
}

void PrintUsage()
{
    std::wcout << LR"(
╔═══════════════════════════════════════════════════════════════════════════╗
║        LDAP Query Tool - Advanced Interactive HTML Viewer v2.0            ║
╚═══════════════════════════════════════════════════════════════════════════╝

USAGE:
    ldap_tool.exe [options]

OPTIONS:
    -s, --server <address>      LDAP server address
    -u, --username <name>       Username for authentication
    -p, --password <pass>       Password for authentication
    -b, --basedn <dn>          Base DN for search
    -f, --filter <filter>      LDAP filter (default: (objectClass=*))
    -a, --attributes <attrs>   Comma-separated attributes or * for all
    -o, --output <file>        Output file path
    -t, --type <format>        Output format: csv, txt, json, xml, html
    --scope <scope>            Search scope: base, one, sub
    --limit <number>           Size limit (default: 10000)
    -h, --help                 Display this help message

HTML VIEWER FEATURES:
    🔍 Advanced Search:
       • Basic Search: Quick keyword search with operators
       • Advanced Search: Multi-condition filtering with AND/OR logic
       • Regex Search: Pattern matching with regular expressions
       • Search Types: Contains, Equals, Starts with, Ends with, Not contains
       • Case-sensitive option
       • Column-specific filtering
       • Numeric comparisons (>, <, >=, <=)

    📊 Comprehensive Statistics:
       • Overview Tab: Dataset summary, fill rates, duplicates
       • Column Details Tab: Per-column statistics
         - Text: Unique values, frequency, length analysis
         - Numeric: Min, Max, Avg, Median, Sum, Std Dev, Quartiles, Range
       • Charts Tab: Visual distribution charts (top 10 columns)
       • Custom Stats Tab: Build custom statistical queries
         - Operations: Count, Unique, Frequency, Sum, Avg, Min, Max, 
                      Median, Mode, Std Deviation, Percentile
         - Apply filters to any column
         - Frequency distribution tables

    📋 Table Features:
       • Fixed height container with smooth scrolling
       • Sticky header row
       • Sortable columns (click header)
       • Pagination: 50/100/250/500/All rows
       • Highlight search terms
       • Hover row highlighting
       • Custom scrollbar styling

    💾 Export Options:
       • Export filtered data to CSV (UTF-8 BOM)
       • Export filtered data to JSON
       • Preserves current filters and sorting

    ⌨️ Keyboard Shortcuts:
       • Ctrl+F: Focus search box
       • Ctrl+S: Export CSV
       • Ctrl+R: Reset all filters
       • Esc: Close modals

    🎨 UI Improvements:
       • Compact header and controls
       • Fixed-height table container (no page scrolling)
       • Smooth horizontal/vertical scrolling
       • Modern gradient design
       • Responsive layout
       • Professional statistics modal

EXAMPLES:
    # Generate advanced HTML viewer
    ldap_tool.exe -o results.html -t html

    # Search with specific attributes
    ldap_tool.exe -a "cn,mail,title,department" -o users.html -t html

    # Export to other formats
    ldap_tool.exe -o data.csv -t csv
    ldap_tool.exe -o data.json -t json

    # Custom search
    ldap_tool.exe -f "(objectClass=user)\" -o users.html -t html
    )" << std::endl;
}

std::wstring StringToWString(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int len=MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &wstr[0], len);
    return wstr;
}

int main(int argc, char* argv[])
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    std::wstring serverAddress=L"labrecon.com";
    std::wstring username=L"admin1";
    std::wstring password=L"admin1hihinopro";
    std::wstring baseDN=L"CN=Users,DC=labrecon,DC=com";
    std::wstring filter=L"(objectClass=*)";
    std::wstring attributesStr=L"*";
    std::wstring outputFile=L"";
    LDAPUtils::OutputFormat format=LDAPUtils::OutputFormat::CONSOLE_ONLY;
    ULONG scope=LDAP_SCOPE_SUBTREE;
    ULONG sizeLimit=10000;

    for (int i=1; i < argc; i++)
    {
        std::string arg=argv[i];

        if (arg == "-h" || arg == "--help")
        {
            PrintUsage();
            return 0;
        }
        else if ((arg == "-s" || arg == "--server") && i + 1 < argc)
        {
            serverAddress=StringToWString(argv[++i]);
        }
        else if ((arg == "-u" || arg == "--username") && i + 1 < argc)
        {
            username=StringToWString(argv[++i]);
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < argc)
        {
            password=StringToWString(argv[++i]);
        }
        else if ((arg == "-b" || arg == "--basedn") && i + 1 < argc)
        {
            baseDN=StringToWString(argv[++i]);
        }
        else if ((arg == "-f" || arg == "--filter") && i + 1 < argc)
        {
            filter=StringToWString(argv[++i]);
        }
        else if ((arg == "-a" || arg == "--attributes") && i + 1 < argc)
        {
            attributesStr=StringToWString(argv[++i]);
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc)
        {
            outputFile=StringToWString(argv[++i]);
        }
        else if ((arg == "-t" || arg == "--type") && i + 1 < argc)
        {
            std::string typeStr=argv[++i];
            if (typeStr == "csv") format=LDAPUtils::OutputFormat::CSV;
            else if (typeStr == "txt") format=LDAPUtils::OutputFormat::TXT;
            else if (typeStr == "json") format=LDAPUtils::OutputFormat::JSON;
            else if (typeStr == "xml") format=LDAPUtils::OutputFormat::XML;
            else if (typeStr == "html") format=LDAPUtils::OutputFormat::HTML;
            else if (typeStr == "console") format=LDAPUtils::OutputFormat::CONSOLE_ONLY;
        }
        else if (arg == "--scope" && i + 1 < argc)
        {
            std::string scopeStr=argv[++i];
            if (scopeStr == "base") scope=LDAP_SCOPE_BASE;
            else if (scopeStr == "one") scope=LDAP_SCOPE_ONELEVEL;
            else if (scopeStr == "sub") scope=LDAP_SCOPE_SUBTREE;
        }
        else if (arg == "--limit" && i + 1 < argc)
        {
            sizeLimit=std::stoi(argv[++i]);
        }
    }

    if (format != LDAPUtils::OutputFormat::CONSOLE_ONLY && outputFile.empty())
    {
        switch (format)
        {
        case LDAPUtils::OutputFormat::CSV: outputFile=L"ldap_results.csv"; break;
        case LDAPUtils::OutputFormat::TXT: outputFile=L"ldap_results.txt"; break;
        case LDAPUtils::OutputFormat::JSON: outputFile=L"ldap_results.json"; break;
        case LDAPUtils::OutputFormat::XML: outputFile=L"ldap_results.xml"; break;
        case LDAPUtils::OutputFormat::HTML: outputFile=L"ldap_results.html"; break;
        default: break;
        }
    }

    std::vector<std::wstring> attributes;
    if (attributesStr == L"*")
    {
        attributes.push_back(L"*");
    }
    else
    {
        std::wstringstream ss(attributesStr);
        std::wstring attr;
        while (std::getline(ss, attr, L','))
        {
            attr.erase(0, attr.find_first_not_of(L" \t"));
            attr.erase(attr.find_last_not_of(L" \t") + 1);
            if (!attr.empty())
                attributes.push_back(attr);
        }
    }

    std::wcout << L"╔═══════════════════════════════════════════════════════════════╗" << std::endl;
    std::wcout << L"║     LDAP Query Tool - Advanced HTML Viewer v2.0               ║" << std::endl;
    std::wcout << L"╚═══════════════════════════════════════════════════════════════╝" << std::endl;
    std::wcout << L"\nConfiguration:" << std::endl;
    std::wcout << L"  Server: " << serverAddress << std::endl;
    std::wcout << L"  Base DN: " << baseDN << std::endl;
    std::wcout << L"  Filter: " << filter << std::endl;
    if (format != LDAPUtils::OutputFormat::CONSOLE_ONLY)
    {
        std::wcout << L"  Output: " << outputFile << std::endl;
    }
    std::wcout << std::endl;

    LDAPUtils::LDAPConnection ldap(serverAddress);

    if (ldap.Connect(username, password, serverAddress))
    {
        std::wcout << L"✓ Connected successfully" << std::endl << std::endl;
        ldap.Search(baseDN, filter, attributes, scope, sizeLimit, format, outputFile);

        if (format == LDAPUtils::OutputFormat::HTML && !outputFile.empty())
        {
            std::wcout << L"\n╔═══════════════════════════════════════════════════════════════╗" << std::endl;
            std::wcout << L"║              Advanced HTML Viewer Generated                   ║" << std::endl;
            std::wcout << L"╚═══════════════════════════════════════════════════════════════╝" << std::endl;
            std::wcout << L"  ✓ 3 Search modes: Basic / Advanced / Regex" << std::endl;
            std::wcout << L"  ✓ Comprehensive statistics with custom builder" << std::endl;
            std::wcout << L"  ✓ Fixed container with smooth scrolling" << std::endl;
            std::wcout << L"  ✓ Visual charts and frequency distributions" << std::endl;
            std::wcout << L"\n  👉 Open: " << outputFile << std::endl;
        }
    }
    else
    {
        std::wcerr << L"✗ Connection failed" << std::endl;
        return 1;
    }

    std::wcout << L"\n✓ Complete! Press any key to exit..." << std::endl;
    std::wcin.get();
    return 0;
}