#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../events/NetworkFlowEvent.h"

struct ObservedNetworkPacket
{
    uint64_t timestampQpc = 0;
    NetworkProtocol protocol = NetworkProtocol::Tcp;
    std::string localAddress;
    uint16_t localPort = 0;
    std::string remoteAddress;
    uint16_t remotePort = 0;
    NetworkDirection direction = NetworkDirection::Unknown;
    uint32_t pid = 0;
    std::wstring processImagePath;
    uint64_t packetBytes = 0;
    std::string source = "npcap";
};

class FlowAggregator
{
public:
    explicit FlowAggregator(std::chrono::milliseconds flowIdlePeriod);
    ~FlowAggregator();

    void ObservePacket(const ObservedNetworkPacket& packet);
    std::vector<NetworkFlowEvent> CollectReadyEvents(uint64_t nowQpc);
    std::vector<NetworkFlowEvent> FlushAll();

private:
    struct Impl;

    static uint64_t MillisecondsToQpc(std::chrono::milliseconds value);

    std::unique_ptr<Impl> m_impl;
};
