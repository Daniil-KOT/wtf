#pragma once

#include "capstone/capstone.h"
#include <fstream>
#include "globals.h"

class CoverageCounter
{
public:
    CoverageCounter(const MasterOptions_t &Opts);
    ~CoverageCounter();
    bool CalculateOverallCov();
    double CalculateCovPercentage(uint64_t AggrCov) { return ((double)(AggrCov) / OverallCov_) * 100; }
    uint64_t OverallCov() const { return OverallCov_; }
    bool Success() const { return HasStats_; }
private:
    CoverageCounter();
    uint64_t OverallCov_;
    std::ifstream *HarnessBinary_;
    std::string Encoded_;
    bool HasStats_;
};