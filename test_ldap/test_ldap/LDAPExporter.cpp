#define _CRT_SECURE_NO_WARNINGS
#include "LDAPExporter.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <iostream>

namespace LDAPUtils
{
    std::string Exporter::EscapeCsvField(const std::string& input)
    {
        std::string output = "\"";
        for (char c : input)
        {
            if (c == '"') output += "\"\"";
            else output += c;
        }
        output += "\"";
        return output;
    }

    std::string Exporter::EscapeJson(const std::string& input)
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
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            default:
                if (c < 32) {
                    char buf[8];
                    sprintf(buf, "\\u%04x", (unsigned char)c);
                    output += buf;
                }
                else {
                    output += c;
                }
            }
        }
        return output;
    }

    std::string Exporter::EscapeXml(const std::string& input)
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

    void Exporter::ExportCsv(const std::wstring& filename, const std::vector<std::wstring>& attributes,
        const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Failed to create CSV file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF"; // UTF-8 BOM

        // Header
        std::string header = EscapeCsvField("DN");
        for (const auto& attr : attributes)
            header += "," + EscapeCsvField(Converters::WStringToUtf8(attr));
        header += "\n";
        file << header;

        // Data rows
        for (const auto& e : entries)
        {
            std::string row = EscapeCsvField(Converters::WStringToUtf8(e.dn));
            for (const auto& attr : attributes)
            {
                std::wstring joined;
                auto it = e.attrs.find(attr);
                if (it != e.attrs.end() && !it->second.empty())
                {
                    for (size_t k = 0; k < it->second.size(); ++k)
                    {
                        if (k > 0) joined += L" | ";
                        joined += it->second[k];
                    }
                }
                row += "," + EscapeCsvField(Converters::WStringToUtf8(joined));
            }
            row += "\n";
            file << row;
        }
        file.close();
        std::wcout << L"✓ CSV exported successfully" << std::endl;
    }

    void Exporter::ExportTxt(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Failed to create TXT file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";

        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto& e = entries[i];
            file << "Entry " << (i + 1) << ":\n";
            file << "DN: " << Converters::WStringToUtf8(e.dn) << "\n";

            for (const auto& attr : e.attrs)
            {
                file << "  " << Converters::WStringToUtf8(attr.first);
                if (attr.second.size() > 1)
                    file << " (" << attr.second.size() << ")";
                file << ": ";

                for (size_t j = 0; j < attr.second.size(); ++j)
                {
                    if (j > 0) file << "; ";
                    file << Converters::WStringToUtf8(attr.second[j]);
                }
                file << "\n";
            }
            file << "\n" << std::string(70, '=') << "\n\n";
        }
        file.close();
        std::wcout << L"✓ TXT exported successfully" << std::endl;
    }

    void Exporter::ExportJson(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Failed to create JSON file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        file << "{\n  \"entries\": [\n";

        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto& e = entries[i];
            file << "    {\n";
            file << "      \"dn\": \"" << EscapeJson(Converters::WStringToUtf8(e.dn)) << "\",\n";
            file << "      \"attributes\": {\n";

            size_t attrCount = 0;
            for (const auto& attr : e.attrs)
            {
                if (attrCount > 0) file << ",\n";
                file << "        \"" << EscapeJson(Converters::WStringToUtf8(attr.first)) << "\": [";

                for (size_t j = 0; j < attr.second.size(); ++j)
                {
                    if (j > 0) file << ", ";
                    file << "\"" << EscapeJson(Converters::WStringToUtf8(attr.second[j])) << "\"";
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
        std::wcout << L"✓ JSON exported successfully" << std::endl;
    }

    void Exporter::ExportXml(const std::wstring& filename, const std::vector<Entry>& entries)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Failed to create XML file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        file << "<ldap_results>\n";

        for (const auto& e : entries)
        {
            file << "  <entry>\n";
            file << "    <dn>" << EscapeXml(Converters::WStringToUtf8(e.dn)) << "</dn>\n";
            file << "    <attributes>\n";

            for (const auto& attr : e.attrs)
            {
                for (const auto& val : attr.second)
                {
                    file << "      <attribute name=\"" << EscapeXml(Converters::WStringToUtf8(attr.first)) << "\">"
                        << EscapeXml(Converters::WStringToUtf8(val)) << "</attribute>\n";
                }
            }

            file << "    </attributes>\n";
            file << "  </entry>\n";
        }

        file << "</ldap_results>\n";
        file.close();
        std::wcout << L"✓ XML exported successfully" << std::endl;
    }

    void Exporter::ExportHtml(const std::wstring& filename, const std::vector<std::wstring>& attributes,
        const std::vector<Entry>& entries, const Statistics& stats)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::wcerr << L"Failed to create HTML file: " << filename << std::endl;
            return;
        }

        file << "\xEF\xBB\xBF";
        file << "<!DOCTYPE html>\n"
            << "<html lang=\"en\">\n"
            << "<head>\n"
            << "    <meta charset=\"UTF-8\">\n"
            << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
            << "    <title>LDAP Query Results - Advanced View</title>\n"
            << "    <style>\n"
            << "        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
            << "        body { \n"
            << "            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;\n"
            << "            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
            << "            height: 100vh;\n"
            << "            overflow: hidden;\n"
            << "        }\n"
            << "        .main-container {\n"
            << "            display: flex;\n"
            << "            flex-direction: column;\n"
            << "            height: 100vh;\n"
            << "            padding: 20px;\n"
            << "            gap: 20px;\n"
            << "        }\n"
            << "        .header {\n"
            << "            background: white;\n"
            << "            padding: 20px 30px;\n"
            << "            border-radius: 12px;\n"
            << "            box-shadow: 0 4px 20px rgba(0,0,0,0.15);\n"
            << "            flex-shrink: 0;\n"
            << "        }\n"
            << "        .header h1 {\n"
            << "            font-size: 24px;\n"
            << "            color: #2d3748;\n"
            << "            margin-bottom: 8px;\n"
            << "        }\n"
            << "        .stats-bar {\n"
            << "            display: flex;\n"
            << "            gap: 30px;\n"
            << "            font-size: 14px;\n"
            << "            color: #4a5568;\n"
            << "            flex-wrap: wrap;\n"
            << "        }\n"
            << "        .stat-item {\n"
            << "            display: flex;\n"
            << "            align-items: center;\n"
            << "            gap: 8px;\n"
            << "        }\n"
            << "        .stat-badge {\n"
            << "            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
            << "            color: white;\n"
            << "            padding: 4px 12px;\n"
            << "            border-radius: 20px;\n"
            << "            font-weight: 600;\n"
            << "            min-width: 40px;\n"
            << "            text-align: center;\n"
            << "        }\n"
            << "        .content-wrapper {\n"
            << "            flex: 1;\n"
            << "            display: flex;\n"
            << "            gap: 20px;\n"
            << "            min-height: 0;\n"
            << "        }\n"
            << "        .sidebar {\n"
            << "            width: 300px;\n"
            << "            background: white;\n"
            << "            border-radius: 12px;\n"
            << "            padding: 20px;\n"
            << "            box-shadow: 0 4px 20px rgba(0,0,0,0.15);\n"
            << "            overflow-y: auto;\n"
            << "            flex-shrink: 0;\n"
            << "        }\n"
            << "        .sidebar h2 {\n"
            << "            font-size: 18px;\n"
            << "            color: #2d3748;\n"
            << "            margin-bottom: 15px;\n"
            << "            padding-bottom: 10px;\n"
            << "            border-bottom: 2px solid #e2e8f0;\n"
            << "            display: flex;\n"
            << "            align-items: center;\n"
            << "            gap: 8px;\n"
            << "        }\n"
            << "        .sidebar h3 {\n"
            << "            font-size: 14px;\n"
            << "            color: #4a5568;\n"
            << "            margin: 15px 0 8px 0;\n"
            << "            font-weight: 600;\n"
            << "        }\n"
            << "        .stat-list {\n"
            << "            list-style: none;\n"
            << "        }\n"
            << "        .stat-list li {\n"
            << "            padding: 8px 0;\n"
            << "            font-size: 13px;\n"
            << "            color: #4a5568;\n"
            << "            display: flex;\n"
            << "            justify-content: space-between;\n"
            << "            align-items: center;\n"
            << "            border-bottom: 1px solid #f7fafc;\n"
            << "        }\n"
            << "        .stat-list li:last-child {\n"
            << "            border-bottom: none;\n"
            << "        }\n"
            << "        .stat-name {\n"
            << "            overflow: hidden;\n"
            << "            text-overflow: ellipsis;\n"
            << "            white-space: nowrap;\n"
            << "            flex: 1;\n"
            << "            margin-right: 10px;\n"
            << "        }\n"
            << "        .stat-count {\n"
            << "            background: #edf2f7;\n"
            << "            color: #2d3748;\n"
            << "            padding: 3px 10px;\n"
            << "            border-radius: 12px;\n"
            << "            font-size: 12px;\n"
            << "            font-weight: 600;\n"
            << "            flex-shrink: 0;\n"
            << "        }\n"
            << "        .main-content {\n"
            << "            flex: 1;\n"
            << "            background: white;\n"
            << "            border-radius: 12px;\n"
            << "            box-shadow: 0 4px 20px rgba(0,0,0,0.15);\n"
            << "            display: flex;\n"
            << "            flex-direction: column;\n"
            << "            min-width: 0;\n"
            << "        }\n"
            << "        .search-toolbar {\n"
            << "            padding: 15px 20px;\n"
            << "            border-bottom: 2px solid #e2e8f0;\n"
            << "            display: flex;\n"
            << "            gap: 10px;\n"
            << "            flex-shrink: 0;\n"
            << "            flex-wrap: wrap;\n"
            << "        }\n"
            << "        .search-box {\n"
            << "            flex: 1;\n"
            << "            min-width: 250px;\n"
            << "            position: relative;\n"
            << "        }\n"
            << "        .search-box input {\n"
            << "            width: 100%;\n"
            << "            padding: 10px 40px 10px 15px;\n"
            << "            border: 2px solid #e2e8f0;\n"
            << "            border-radius: 8px;\n"
            << "            font-size: 14px;\n"
            << "            transition: all 0.3s;\n"
            << "        }\n"
            << "        .search-box input:focus {\n"
            << "            outline: none;\n"
            << "            border-color: #667eea;\n"
            << "            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);\n"
            << "        }\n"
            << "        .search-icon {\n"
            << "            position: absolute;\n"
            << "            right: 12px;\n"
            << "            top: 50%;\n"
            << "            transform: translateY(-50%);\n"
            << "            color: #cbd5e0;\n"
            << "            font-size: 18px;\n"
            << "        }\n"
            << "        .filter-buttons {\n"
            << "            display: flex;\n"
            << "            gap: 8px;\n"
            << "            flex-wrap: wrap;\n"
            << "        }\n"
            << "        .filter-btn {\n"
            << "            padding: 8px 16px;\n"
            << "            border: 2px solid #e2e8f0;\n"
            << "            background: white;\n"
            << "            border-radius: 8px;\n"
            << "            font-size: 13px;\n"
            << "            cursor: pointer;\n"
            << "            transition: all 0.3s;\n"
            << "            white-space: nowrap;\n"
            << "        }\n"
            << "        .filter-btn:hover {\n"
            << "            background: #f7fafc;\n"
            << "            border-color: #cbd5e0;\n"
            << "        }\n"
            << "        .filter-btn.active {\n"
            << "            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
            << "            color: white;\n"
            << "            border-color: transparent;\n"
            << "        }\n"
            << "        .table-wrapper {\n"
            << "            flex: 1;\n"
            << "            overflow: auto;\n"
            << "            position: relative;\n"
            << "        }\n"
            << "        table {\n"
            << "            width: 100%;\n"
            << "            border-collapse: collapse;\n"
            << "            font-size: 13px;\n"
            << "        }\n"
            << "        thead {\n"
            << "            position: sticky;\n"
            << "            top: 0;\n"
            << "            z-index: 10;\n"
            << "            background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);\n"
            << "        }\n"
            << "        th {\n"
            << "            padding: 12px 15px;\n"
            << "            text-align: left;\n"
            << "            font-weight: 600;\n"
            << "            color: #2d3748;\n"
            << "            border-bottom: 2px solid #e2e8f0;\n"
            << "            white-space: nowrap;\n"
            << "            font-size: 11px;\n"
            << "            text-transform: uppercase;\n"
            << "            letter-spacing: 0.5px;\n"
            << "            cursor: pointer;\n"
            << "            user-select: none;\n"
            << "        }\n"
            << "        th:hover {\n"
            << "            background: #edf2f7;\n"
            << "        }\n"
            << "        th.sortable:after {\n"
            << "            content: ' ⇅';\n"
            << "            opacity: 0.3;\n"
            << "        }\n"
            << "        th.sort-asc:after {\n"
            << "            content: ' ↑';\n"
            << "            opacity: 1;\n"
            << "        }\n"
            << "        th.sort-desc:after {\n"
            << "            content: ' ↓';\n"
            << "            opacity: 1;\n"
            << "        }\n"
            << "        th:first-child {\n"
            << "            width: 50px;\n"
            << "            text-align: center;\n"
            << "        }\n"
            << "        td {\n"
            << "            padding: 12px 15px;\n"
            << "            border-bottom: 1px solid #f7fafc;\n"
            << "            color: #4a5568;\n"
            << "            max-width: 300px;\n"
            << "            overflow: hidden;\n"
            << "            text-overflow: ellipsis;\n"
            << "            white-space: nowrap;\n"
            << "        }\n"
            << "        td:first-child {\n"
            << "            text-align: center;\n"
            << "            color: #a0aec0;\n"
            << "            font-weight: 600;\n"
            << "        }\n"
            << "        tbody tr {\n"
            << "            transition: all 0.2s;\n"
            << "        }\n"
            << "        tbody tr:hover {\n"
            << "            background: linear-gradient(90deg, #f7fafc 0%, #edf2f7 100%);\n"
            << "            transform: scale(1.001);\n"
            << "        }\n"
            << "        .dn-cell {\n"
            << "            max-width: 400px;\n"
            << "            color: #667eea;\n"
            << "            font-weight: 500;\n"
            << "            cursor: pointer;\n"
            << "        }\n"
            << "        .dn-cell:hover {\n"
            << "            color: #764ba2;\n"
            << "            text-decoration: underline;\n"
            << "        }\n"
            << "        .no-results {\n"
            << "            display: none;\n"
            << "            text-align: center;\n"
            << "            padding: 80px 20px;\n"
            << "            color: #a0aec0;\n"
            << "        }\n"
            << "        .no-results svg {\n"
            << "            width: 80px;\n"
            << "            height: 80px;\n"
            << "            opacity: 0.3;\n"
            << "            margin-bottom: 20px;\n"
            << "        }\n"
            << "        .no-results h3 {\n"
            << "            font-size: 20px;\n"
            << "            color: #718096;\n"
            << "            margin-bottom: 8px;\n"
            << "        }\n"
            << "        .no-results p {\n"
            << "            font-size: 14px;\n"
            << "        }\n"
            << "        .export-buttons {\n"
            << "            margin-top: 15px;\n"
            << "            padding-top: 15px;\n"
            << "            border-top: 2px solid #e2e8f0;\n"
            << "        }\n"
            << "        .export-btn {\n"
            << "            display: inline-block;\n"
            << "            padding: 8px 16px;\n"
            << "            margin: 5px;\n"
            << "            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
            << "            color: white;\n"
            << "            border: none;\n"
            << "            border-radius: 6px;\n"
            << "            cursor: pointer;\n"
            << "            font-size: 12px;\n"
            << "            text-decoration: none;\n"
            << "            transition: transform 0.2s;\n"
            << "        }\n"
            << "        .export-btn:hover {\n"
            << "            transform: translateY(-2px);\n"
            << "        }\n"
            << "        ::-webkit-scrollbar {\n"
            << "            width: 10px;\n"
            << "            height: 10px;\n"
            << "        }\n"
            << "        ::-webkit-scrollbar-track {\n"
            << "            background: #f7fafc;\n"
            << "        }\n"
            << "        ::-webkit-scrollbar-thumb {\n"
            << "            background: #cbd5e0;\n"
            << "            border-radius: 5px;\n"
            << "        }\n"
            << "        ::-webkit-scrollbar-thumb:hover {\n"
            << "            background: #a0aec0;\n"
            << "        }\n"
            << "        @media (max-width: 1200px) {\n"
            << "            .sidebar {\n"
            << "                width: 250px;\n"
            << "            }\n"
            << "        }\n"
            << "        @media (max-width: 900px) {\n"
            << "            .content-wrapper {\n"
            << "                flex-direction: column;\n"
            << "            }\n"
            << "            .sidebar {\n"
            << "                width: 100%;\n"
            << "                max-height: 300px;\n"
            << "            }\n"
            << "        }\n"
            << "    </style>\n"
            << "</head>\n"
            << "<body>\n"
            << "    <div class=\"main-container\">\n"
            << "        <div class=\"header\">\n"
            << "            <h1>LDAP Query Results</h1>\n"
            << "            <div class=\"stats-bar\">\n"
            << "                <div class=\"stat-item\">\n"
            << "                    <span>Total:</span>\n"
            << "                    <span class=\"stat-badge\" id=\"totalEntries\">" << entries.size() << "</span>\n"
            << "                </div>\n"
            << "                <div class=\"stat-item\">\n"
            << "                    <span>Attributes:</span>\n"
            << "                    <span class=\"stat-badge\">" << attributes.size() << "</span>\n"
            << "                </div>\n"
            << "                <div class=\"stat-item\">\n"
            << "                    <span>Visible:</span>\n"
            << "                    <span class=\"stat-badge\" id=\"visibleCount\">" << entries.size() << "</span>\n"
            << "                </div>\n"
            << "                <div class=\"stat-item\">\n"
            << "                    <span>Selected:</span>\n"
            << "                    <span class=\"stat-badge\" id=\"selectedCount\">0</span>\n"
            << "                </div>\n"
            << "            </div>\n"
            << "        </div>\n"
            << "        <div class=\"content-wrapper\">\n"
            << "            <div class=\"sidebar\">\n"
            << "                <h2>Statistics</h2>\n"
            << "                <div class=\"stat-item\" style=\"margin-bottom: 10px;\">\n"
            << "                    <span style=\"color: #2d3748; font-weight: 600;\">Total Records:</span>\n"
            << "                    <span class=\"stat-count\">" << entries.size() << "</span>\n"
            << "                </div>\n";

        // Object class statistics
        if (!stats.objectClassCount.empty())
        {
            file << "                <h3>Object Classes</h3>\n"
                << "                <ul class=\"stat-list\">\n";

            std::vector<std::pair<std::wstring, int>> sortedOC(stats.objectClassCount.begin(), stats.objectClassCount.end());
            std::sort(sortedOC.begin(), sortedOC.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });

            for (const auto& oc : sortedOC)
            {
                file << "                    <li><span class='stat-name' title='" << EscapeXml(Converters::WStringToUtf8(oc.first)) << "'>"
                    << EscapeXml(Converters::WStringToUtf8(oc.first))
                    << "</span><span class='stat-count'>" << oc.second << "</span></li>\n";
            }
            file << "                </ul>\n";
        }

        // Top attributes
        std::vector<std::pair<std::wstring, int>> sortedAttrs(stats.attributeCount.begin(), stats.attributeCount.end());
        std::sort(sortedAttrs.begin(), sortedAttrs.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        file << "                <h3>Top Attributes</h3>\n"
            << "                <ul class=\"stat-list\">\n";
        int count = 0;
        for (const auto& attr : sortedAttrs)
        {
            if (count++ >= 15) break;
            file << "                    <li><span class='stat-name' title='" << EscapeXml(Converters::WStringToUtf8(attr.first)) << "'>"
                << EscapeXml(Converters::WStringToUtf8(attr.first))
                << "</span><span class='stat-count'>" << attr.second << "</span></li>\n";
        }
        file << "                </ul>\n"
            << "                <div class=\"export-buttons\">\n"
            << "                    <h3>Export Visible</h3>\n"
            << "                    <button class=\"export-btn\" onclick=\"exportToCSV()\">📄 CSV</button>\n"
            << "                    <button class=\"export-btn\" onclick=\"exportToJSON()\">📋 JSON</button>\n"
            << "                    <button class=\"export-btn\" onclick=\"copySelected()\">📑 Copy</button>\n"
            << "                </div>\n"
            << "            </div>\n"
            << "            <div class=\"main-content\">\n"
            << "                <div class=\"search-toolbar\">\n"
            << "                    <div class=\"search-box\">\n"
            << "                        <input type=\"text\" id=\"searchInput\" placeholder=\"🔎 Search by DN or any attribute value...\">\n"
            << "                        <span class=\"search-icon\">⌕</span>\n"
            << "                    </div>\n"
            << "                    <div class=\"filter-buttons\">\n"
            << "                        <button class=\"filter-btn active\" data-filter=\"all\">All</button>\n"
            << "                        <button class=\"filter-btn\" data-filter=\"user\">Users</button>\n"
            << "                        <button class=\"filter-btn\" data-filter=\"group\">Groups</button>\n"
            << "                        <button class=\"filter-btn\" data-filter=\"computer\">Computers</button>\n"
            << "                    </div>\n"
            << "                </div>\n"
            << "                <div class=\"table-wrapper\">\n"
            << "                    <table id=\"dataTable\">\n"
            << "                        <thead>\n"
            << "                            <tr>\n"
            << "                                <th>#</th>\n"
            << "                                <th class=\"sortable\" data-column=\"dn\">DN</th>\n";

        int colIndex = 2;
        for (const auto& attr : attributes)
        {
            file << "                                <th class=\"sortable\" data-column=\"" << colIndex++ << "\">"
                << EscapeXml(Converters::WStringToUtf8(attr)) << "</th>\n";
        }

        file << "                            </tr>\n"
            << "                        </thead>\n"
            << "                        <tbody>\n";

        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto& e = entries[i];
            std::string entryType = "unknown";
            auto ocIt = e.attrs.find(L"objectClass");
            if (ocIt != e.attrs.end())
            {
                for (const auto& oc : ocIt->second)
                {
                    std::wstring ocLower = Converters::ToLower(oc);
                    if (ocLower == L"user" || ocLower == L"person") {
                        entryType = "user";
                        break;
                    }
                    else if (ocLower == L"group") {
                        entryType = "group";
                        break;
                    }
                    else if (ocLower == L"computer") {
                        entryType = "computer";
                        break;
                    }
                }
            }

            file << "                            <tr data-type=\"" << entryType << "\" data-index=\"" << i << "\">\n"
                << "                                <td>" << (i + 1) << "</td>\n"
                << "                                <td class=\"dn-cell\" title=\"" << EscapeXml(Converters::WStringToUtf8(e.dn)) << "\">"
                << EscapeXml(Converters::WStringToUtf8(e.dn)) << "</td>\n";

            for (const auto& attr : attributes)
            {
                std::wstring joined;
                auto it = e.attrs.find(attr);
                if (it != e.attrs.end() && !it->second.empty())
                {
                    for (size_t k = 0; k < it->second.size(); ++k)
                    {
                        if (k > 0) joined += L" | ";
                        joined += it->second[k];
                    }
                }
                std::string cellContent = Converters::WStringToUtf8(joined);
                file << "                                <td title=\"" << EscapeXml(cellContent) << "\">" << EscapeXml(cellContent) << "</td>\n";
            }

            file << "                            </tr>\n";
        }

        file << "                        </tbody>\n"
            << "                    </table>\n"
            << "                    <div class=\"no-results\" id=\"noResults\">\n"
            << "                        <svg xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\">\n"
            << "                            <path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z\" />\n"
            << "                        </svg>\n"
            << "                        <h3>No results found</h3>\n"
            << "                        <p>Try adjusting your search or filter</p>\n"
            << "                    </div>\n"
            << "                </div>\n"
            << "            </div>\n"
            << "        </div>\n"
            << "    </div>\n"
            << "    <script>\n"
            << "        const searchInput = document.getElementById('searchInput');\n"
            << "        const table = document.getElementById('dataTable');\n"
            << "        const tbody = table.querySelector('tbody');\n"
            << "        const noResults = document.getElementById('noResults');\n"
            << "        const rows = Array.from(tbody.querySelectorAll('tr'));\n"
            << "        const visibleCount = document.getElementById('visibleCount');\n"
            << "        const selectedCount = document.getElementById('selectedCount');\n"
            << "        const filterButtons = document.querySelectorAll('.filter-btn');\n"
            << "        let currentFilter = 'all';\n"
            << "        let currentSearch = '';\n"
            << "        let currentSort = { column: null, direction: 'asc' };\n"
            << "        let selectedRows = new Set();\n"
            << "        function updateDisplay() {\n"
            << "            let visibleRows = 0;\n"
            << "            rows.forEach(row => {\n"
            << "                const text = row.textContent.toLowerCase();\n"
            << "                const type = row.dataset.type;\n"
            << "                const matchesSearch = currentSearch === '' || text.includes(currentSearch);\n"
            << "                const matchesFilter = currentFilter === 'all' || type === currentFilter;\n"
            << "                if (matchesSearch && matchesFilter) {\n"
            << "                    row.style.display = '';\n"
            << "                    visibleRows++;\n"
            << "                } else {\n"
            << "                    row.style.display = 'none';\n"
            << "                }\n"
            << "            });\n"
            << "            visibleCount.textContent = visibleRows;\n"
            << "            if (visibleRows === 0) {\n"
            << "                table.style.display = 'none';\n"
            << "                noResults.style.display = 'block';\n"
            << "            } else {\n"
            << "                table.style.display = 'table';\n"
            << "                noResults.style.display = 'none';\n"
            << "            }\n"
            << "        }\n"
            << "        searchInput.addEventListener('input', function() {\n"
            << "            currentSearch = this.value.toLowerCase();\n"
            << "            updateDisplay();\n"
            << "        });\n"
            << "        filterButtons.forEach(btn => {\n"
            << "            btn.addEventListener('click', function() {\n"
            << "                filterButtons.forEach(b => b.classList.remove('active'));\n"
            << "                this.classList.add('active');\n"
            << "                currentFilter = this.dataset.filter;\n"
            << "                updateDisplay();\n"
            << "            });\n"
            << "        });\n"
            << "        document.querySelectorAll('th.sortable').forEach((th, index) => {\n"
            << "            th.addEventListener('click', function() {\n"
            << "                const column = parseInt(this.dataset.column) || index;\n"
            << "                if (currentSort.column === column) {\n"
            << "                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';\n"
            << "                } else {\n"
            << "                    currentSort.column = column;\n"
            << "                    currentSort.direction = 'asc';\n"
            << "                }\n"
            << "                document.querySelectorAll('th.sortable').forEach(h => {\n"
            << "                    h.classList.remove('sort-asc', 'sort-desc');\n"
            << "                });\n"
            << "                this.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');\n"
            << "                const visibleRows = rows.filter(r => r.style.display !== 'none');\n"
            << "                visibleRows.sort((a, b) => {\n"
            << "                    const aVal = a.cells[column].textContent.trim();\n"
            << "                    const bVal = b.cells[column].textContent.trim();\n"
            << "                    const comparison = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });\n"
            << "                    return currentSort.direction === 'asc' ? comparison : -comparison;\n"
            << "                });\n"
            << "                visibleRows.forEach(row => tbody.appendChild(row));\n"
            << "            });\n"
            << "        });\n"
            << "        tbody.addEventListener('click', function(e) {\n"
            << "            if (e.target.classList.contains('dn-cell')) {\n"
            << "                const dn = e.target.getAttribute('title');\n"
            << "                navigator.clipboard.writeText(dn).then(() => {\n"
            << "                    const original = e.target.textContent;\n"
            << "                    e.target.textContent = '✓ Copied!';\n"
            << "                    e.target.style.color = '#48bb78';\n"
            << "                    setTimeout(() => {\n"
            << "                        e.target.textContent = original;\n"
            << "                        e.target.style.color = '';\n"
            << "                    }, 1500);\n"
            << "                }).catch(err => {\n"
            << "                    console.error('Failed to copy:', err);\n"
            << "                    alert('Failed to copy to clipboard');\n"
            << "                });\n"
            << "            }\n"
            << "        });\n"
            << "        tbody.addEventListener('click', function(e) {\n"
            << "            if (e.ctrlKey || e.metaKey) {\n"
            << "                const row = e.target.closest('tr');\n"
            << "                if (row) {\n"
            << "                    const index = row.dataset.index;\n"
            << "                    if (selectedRows.has(index)) {\n"
            << "                        selectedRows.delete(index);\n"
            << "                        row.style.background = '';\n"
            << "                    } else {\n"
            << "                        selectedRows.add(index);\n"
            << "                        row.style.background = '#e6f7ff';\n"
            << "                    }\n"
            << "                    selectedCount.textContent = selectedRows.size;\n"
            << "                }\n"
            << "            }\n"
            << "        });\n"
            << "        function exportToCSV() {\n"
            << "            const visibleRows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.style.display !== 'none');\n"
            << "            if (visibleRows.length === 0) {\n"
            << "                alert('No visible rows to export');\n"
            << "                return;\n"
            << "            }\n"
            << "            let csv = '';\n"
            << "            const headers = Array.from(document.querySelectorAll('th')).map(th => th.textContent.trim());\n"
            << "            csv += headers.map(h => '\"' + h.replace(/\"/g, '\"\"') + '\"').join(',') + '\\n';\n"
            << "            visibleRows.forEach(row => {\n"
            << "                const values = Array.from(row.cells).map(cell => {\n"
            << "                    const val = cell.getAttribute('title') || cell.textContent.trim();\n"
            << "                    return '\"' + val.replace(/\"/g, '\"\"') + '\"';\n"
            << "                });\n"
            << "                csv += values.join(',') + '\\n';\n"
            << "            });\n"
            << "            const blob = new Blob(['\\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });\n"
            << "            const link = document.createElement('a');\n"
            << "            link.href = URL.createObjectURL(blob);\n"
            << "            link.download = 'ldap_export_' + new Date().toISOString().split('T')[0] + '.csv';\n"
            << "            link.click();\n"
            << "        }\n"
            << "        function exportToJSON() {\n"
            << "            const visibleRows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.style.display !== 'none');\n"
            << "            if (visibleRows.length === 0) {\n"
            << "                alert('No visible rows to export');\n"
            << "                return;\n"
            << "            }\n"
            << "            const headers = Array.from(document.querySelectorAll('th')).map(th => th.textContent.trim());\n"
            << "            const data = visibleRows.map(row => {\n"
            << "                const obj = {};\n"
            << "                Array.from(row.cells).forEach((cell, i) => {\n"
            << "                    obj[headers[i]] = cell.getAttribute('title') || cell.textContent.trim();\n"
            << "                });\n"
            << "                return obj;\n"
            << "            });\n"
            << "            const json = JSON.stringify({ entries: data }, null, 2);\n"
            << "            const blob = new Blob([json], { type: 'application/json' });\n"
            << "            const link = document.createElement('a');\n"
            << "            link.href = URL.createObjectURL(blob);\n"
            << "            link.download = 'ldap_export_' + new Date().toISOString().split('T')[0] + '.json';\n"
            << "            link.click();\n"
            << "        }\n"
            << "        function copySelected() {\n"
            << "            if (selectedRows.size === 0) {\n"
            << "                alert('No rows selected. Use Ctrl+Click to select rows.');\n"
            << "                return;\n"
            << "            }\n"
            << "            const headers = Array.from(document.querySelectorAll('th')).map(th => th.textContent.trim());\n"
            << "            let text = headers.join('\\t') + '\\n';\n"
            << "            selectedRows.forEach(index => {\n"
            << "                const row = tbody.querySelector(`tr[data-index=\"${index}\"]`);\n"
            << "                if (row) {\n"
            << "                    const values = Array.from(row.cells).map(cell => \n"
            << "                        cell.getAttribute('title') || cell.textContent.trim()\n"
            << "                    );\n"
            << "                    text += values.join('\\t') + '\\n';\n"
            << "                }\n"
            << "            });\n"
            << "            navigator.clipboard.writeText(text).then(() => {\n"
            << "                alert('Selected rows copied to clipboard!');\n"
            << "            }).catch(err => {\n"
            << "                console.error('Failed to copy:', err);\n"
            << "                alert('Failed to copy to clipboard');\n"
            << "            });\n"
            << "        }\n"
            << "        document.addEventListener('keydown', function(e) {\n"
            << "            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {\n"
            << "                e.preventDefault();\n"
            << "                searchInput.focus();\n"
            << "                searchInput.select();\n"
            << "            }\n"
            << "            if ((e.ctrlKey || e.metaKey) && e.key === 'a' && document.activeElement === document.body) {\n"
            << "                e.preventDefault();\n"
            << "                const visibleRows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.style.display !== 'none');\n"
            << "                visibleRows.forEach(row => {\n"
            << "                    const index = row.dataset.index;\n"
            << "                    selectedRows.add(index);\n"
            << "                    row.style.background = '#e6f7ff';\n"
            << "                });\n"
            << "                selectedCount.textContent = selectedRows.size;\n"
            << "            }\n"
            << "            if (e.key === 'Escape') {\n"
            << "                selectedRows.forEach(index => {\n"
            << "                    const row = tbody.querySelector(`tr[data-index=\"${index}\"]`);\n"
            << "                    if (row) row.style.background = '';\n"
            << "                });\n"
            << "                selectedRows.clear();\n"
            << "                selectedCount.textContent = '0';\n"
            << "                searchInput.value = '';\n"
            << "                currentSearch = '';\n"
            << "                updateDisplay();\n"
            << "            }\n"
            << "        });\n"
            << "        console.log('LDAP Query Tool initialized');\n"
            << "        console.log('Total entries:', rows.length);\n"
            << "        console.log('Keyboard shortcuts:');\n"
            << "        console.log('  Ctrl+F: Focus search');\n"
            << "        console.log('  Ctrl+Click: Select rows');\n"
            << "        console.log('  Ctrl+A: Select all visible');\n"
            << "        console.log('  Escape: Clear selection');\n"
            << "    </script>\n"
            << "</body>\n"
            << "</html>\n";

        file.close();
        std::wcout << L"HTML exported successfully with advanced features" << std::endl;
    }
}