#include "LDAPStatistics.h"
#include "LDAPConverters.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace LDAPUtils
{
    Statistics StatisticsCalculator::Calculate(const std::vector<Entry>& entries)
    {
        Statistics stats;
        stats.totalEntries = static_cast<int>(entries.size());

        if (entries.empty())
        {
            return stats;
        }

        std::set<std::wstring> allAttrs;

        for (const auto& entry : entries)
        {
            for (const auto& attr : entry.attrs)
            {
                allAttrs.insert(attr.first);
                stats.attributeCount[attr.first]++;

                // Count unique values for specific attributes
                if (attr.first == L"objectClass" ||
                    attr.first == L"sAMAccountType" ||
                    attr.first == L"department" ||
                    attr.first == L"title" ||
                    attr.first == L"userAccountControl" ||
                    attr.first == L"groupType")
                {
                    for (const auto& val : attr.second)
                    {
                        stats.uniqueValues[attr.first].insert(val);
                    }
                }

                // Count object classes
                if (attr.first == L"objectClass")
                {
                    for (const auto& oc : attr.second)
                    {
                        stats.objectClassCount[oc]++;
                    }
                }
            }
        }

        stats.totalAttributes = static_cast<int>(allAttrs.size());
        return stats;
    }

    void StatisticsCalculator::PrintStatistics(const Statistics& stats)
    {
        std::wcout << L"\n╔═══════════════════════════════════════════════════════════════╗" << std::endl;
        std::wcout << L"║                     SEARCH STATISTICS                         ║" << std::endl;
        std::wcout << L"╚═══════════════════════════════════════════════════════════════╝" << std::endl;

        std::wcout << L"\n📊 Summary:" << std::endl;
        std::wcout << L"  Total Entries: " << stats.totalEntries << std::endl;
        std::wcout << L"  Total Unique Attributes: " << stats.totalAttributes << std::endl;

        if (!stats.objectClassCount.empty())
        {
            std::wcout << L"\n📦 Object Classes Distribution:" << std::endl;

            // Sort by count (descending)
            std::vector<std::pair<std::wstring, int>> sortedOC(
                stats.objectClassCount.begin(),
                stats.objectClassCount.end()
            );
            std::sort(sortedOC.begin(), sortedOC.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });

            for (const auto& oc : sortedOC)
            {
                std::wcout << L"  " << std::setw(30) << std::left << oc.first
                    << L": " << std::setw(6) << std::right << oc.second
                    << L" (" << std::fixed << std::setprecision(1)
                    << (100.0 * oc.second / stats.totalEntries) << L"%)" << std::endl;
            }
        }

        std::wcout << L"\n🔑 Top 15 Most Common Attributes:" << std::endl;
        std::vector<std::pair<std::wstring, int>> sortedAttrs(
            stats.attributeCount.begin(),
            stats.attributeCount.end()
        );
        std::sort(sortedAttrs.begin(), sortedAttrs.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        int count = 0;
        for (const auto& attr : sortedAttrs)
        {
            if (count++ >= 15) break;
            std::wcout << L"  " << std::setw(35) << std::left << attr.first
                << L": " << std::setw(6) << std::right << attr.second
                << L" (" << std::fixed << std::setprecision(1)
                << (100.0 * attr.second / stats.totalEntries) << L"%)" << std::endl;
        }

        // Show unique value counts for tracked attributes
        if (!stats.uniqueValues.empty())
        {
            std::wcout << L"\n📈 Unique Values:" << std::endl;
            for (const auto& uv : stats.uniqueValues)
            {
                std::wcout << L"  " << std::setw(35) << std::left << uv.first
                    << L": " << uv.second.size() << L" unique values" << std::endl;

                // Show top 5 values if reasonable size
                if (uv.second.size() <= 20)
                {
                    int vcount = 0;
                    for (const auto& val : uv.second)
                    {
                        if (vcount++ >= 5) break;
                        std::wcout << L"      → " << val << std::endl;
                    }
                    if (uv.second.size() > 5)
                    {
                        std::wcout << L"      ... and " << (uv.second.size() - 5) << L" more" << std::endl;
                    }
                }
            }
        }

        std::wcout << L"\n" << std::wstring(67, L'═') << std::endl;
    }

    std::wstring StatisticsCalculator::GenerateStatisticsReport(const Statistics& stats)
    {
        std::wstringstream report;
        report << L"<div class='stats-panel'>";
        report << L"<h2>📊 Statistics</h2>";
        report << L"<div class='stat-item'><span class='stat-label'>Total Entries:</span> <span class='stat-value'>"
            << stats.totalEntries << L"</span></div>";
        report << L"<div class='stat-item'><span class='stat-label'>Unique Attributes:</span> <span class='stat-value'>"
            << stats.totalAttributes << L"</span></div>";

        if (!stats.objectClassCount.empty())
        {
            report << L"<h3>Object Classes</h3><ul>";

            // Sort by count
            std::vector<std::pair<std::wstring, int>> sortedOC(
                stats.objectClassCount.begin(),
                stats.objectClassCount.end()
            );
            std::sort(sortedOC.begin(), sortedOC.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });

            for (const auto& oc : sortedOC)
            {
                double percentage = (100.0 * oc.second / stats.totalEntries);
                report << L"<li>" << oc.first << L": <strong>" << oc.second
                    << L"</strong> (" << std::fixed << std::setprecision(1)
                    << percentage << L"%)</li>";
            }
            report << L"</ul>";
        }

        // Top attributes
        if (!stats.attributeCount.empty())
        {
            report << L"<h3>Top Attributes</h3><ul>";

            std::vector<std::pair<std::wstring, int>> sortedAttrs(
                stats.attributeCount.begin(),
                stats.attributeCount.end()
            );
            std::sort(sortedAttrs.begin(), sortedAttrs.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });

            int count = 0;
            for (const auto& attr : sortedAttrs)
            {
                if (count++ >= 10) break;
                double percentage = (100.0 * attr.second / stats.totalEntries);
                report << L"<li>" << attr.first << L": <strong>" << attr.second
                    << L"</strong> (" << std::fixed << std::setprecision(1)
                    << percentage << L"%)</li>";
            }
            report << L"</ul>";
        }

        report << L"</div>";
        return report.str();
    }
}