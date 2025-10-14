#pragma once
#include "LDAPTypes.h"
#include "LDAPConverters.h"

namespace LDAPUtils
{
    class Exporter
    {
    public:
        static void ExportCsv(const std::wstring& filename, const std::vector<std::wstring>& attributes,
            const std::vector<Entry>& entries);
        static void ExportTxt(const std::wstring& filename, const std::vector<Entry>& entries);
        static void ExportJson(const std::wstring& filename, const std::vector<Entry>& entries);
        static void ExportXml(const std::wstring& filename, const std::vector<Entry>& entries);
        static void ExportHtml(const std::wstring& filename, const std::vector<std::wstring>& attributes,
            const std::vector<Entry>& entries, const Statistics& stats);

    private:
        static std::string EscapeCsvField(const std::string& input);
        static std::string EscapeJson(const std::string& input);
        static std::string EscapeXml(const std::string& input);
    };
}