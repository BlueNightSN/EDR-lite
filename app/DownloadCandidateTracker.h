#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "../core/config/AppConfig.h"
#include "../core/events/DownloadFileEvent.h"

class Logger;

class DownloadCandidateTracker
{
public:
    explicit DownloadCandidateTracker(const AppConfig& config);

    void ObserveDownloadActivity(const DownloadFileEvent& event, Logger& logger);
    std::vector<std::wstring> CollectStableCandidates(Logger& logger);

private:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct Candidate
    {
        std::wstring path;
        TimePoint firstSeen;
        TimePoint lastChangeTime;
        uintmax_t lastObservedSize = 0;
        uintmax_t previousObservedSize = 0;
        bool hasObservedSize = false;
    };

    static std::wstring NormalizePathKey(const std::wstring& path);

    std::chrono::milliseconds m_quietPeriod;
    std::unordered_map<std::wstring, Candidate> m_candidates;
};

