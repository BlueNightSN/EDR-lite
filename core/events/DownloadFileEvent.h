#pragma once

#include <cstdint>
#include <string>

#include "EventMetadata.h"

struct DownloadFileEvent
{
    uint64_t timestampQpc = 0;
    std::wstring path;

    EventMetadata Metadata() const
    {
        return EventMetadata{ timestampQpc };
    }
};
