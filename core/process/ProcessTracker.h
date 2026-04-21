#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../events/ProcessStartEvent.h"

struct ProcessState
{
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::wstring imagePath;
    std::wstring parentImagePath;
    std::wstring commandLine;
    std::chrono::steady_clock::time_point firstSeen{};
    std::chrono::steady_clock::time_point lastSeen{};
};

class ProcessTracker
{
public:
    void ObserveProcessStart(const ProcessStartEvent& event);
    std::optional<ProcessState> TryGet(uint32_t pid) const;
    std::vector<ProcessState> Snapshot() const;
    std::size_t Size() const;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<uint32_t, ProcessState> m_processes;
};

