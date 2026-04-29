#pragma once

#include <cstdint>
#include <string>

#include "EventMetadata.h"

enum class NetworkProtocol
{
    Tcp,
    Udp
};

enum class NetworkDirection
{
    Unknown,
    Inbound,
    Outbound
};

struct NetworkFlowEvent
{
    uint64_t timestampStartQpc = 0;
    uint64_t timestampLastQpc = 0;
    NetworkProtocol protocol = NetworkProtocol::Tcp;
    std::string localAddress;
    uint16_t localPort = 0;
    std::string remoteAddress;
    uint16_t remotePort = 0;
    uint64_t packetCount = 0;
    uint64_t bytesTotal = 0;
    uint64_t bytesIn = 0;
    uint64_t bytesOut = 0;
    NetworkDirection direction = NetworkDirection::Unknown;
    uint32_t pid = 0;
    std::wstring processImagePath;
    std::string source = "npcap";

    EventMetadata Metadata() const
    {
        return EventMetadata{ timestampLastQpc };
    }
};
