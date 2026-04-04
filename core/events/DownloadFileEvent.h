#pragma once

#include <cstdint>
#include <string>

struct DownloadFileEvent
{
    uint64_t timestampQpc = 0;
    std::wstring path;
};
