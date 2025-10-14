#pragma once
#include "LDAPTypes.h"
#include <iostream>

namespace LDAPUtils
{
    class StatisticsCalculator
    {
    public:
        static Statistics Calculate(const std::vector<Entry>& entries);
        static void PrintStatistics(const Statistics& stats);
        static std::wstring GenerateStatisticsReport(const Statistics& stats);
    };
}