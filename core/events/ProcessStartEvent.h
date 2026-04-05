#pragma once
#include <string>
#include <cstdint>

struct ProcessStartEvent
{
    uint64_t timestampQpc = 0;   // raw timestamp (QPC-like from ETW header)
    uint32_t pid = 0;
    uint32_t ppid = 0;

    std::wstring imagePath;
    std::wstring parentImagePath;
    std::wstring commandLine;
};
