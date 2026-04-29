#include "FlowAggregator.h"

#include <cstddef>
#include <functional>
#include <unordered_map>
#include <utility>

namespace
{
template <typename T>
void HashCombine(std::size_t& seed, const T& value)
{
    const std::size_t hashed = std::hash<T>{}(value);
    seed ^= hashed + 0x9e3779b9u + (seed << 6) + (seed >> 2);
}
} // namespace

struct FlowKey
{
    NetworkProtocol protocol = NetworkProtocol::Tcp;
    std::string localAddress;
    uint16_t localPort = 0;
    std::string remoteAddress;
    uint16_t remotePort = 0;

    bool operator==(const FlowKey& other) const
    {
        return protocol == other.protocol
            && localPort == other.localPort
            && remotePort == other.remotePort
            && localAddress == other.localAddress
            && remoteAddress == other.remoteAddress;
    }
};

struct FlowState
{
    uint64_t timestampStartQpc = 0;
    uint64_t timestampLastQpc = 0;
    uint64_t packetCount = 0;
    uint64_t bytesTotal = 0;
    uint64_t bytesIn = 0;
    uint64_t bytesOut = 0;
    NetworkDirection direction = NetworkDirection::Unknown;
    uint32_t pid = 0;
    std::wstring processImagePath;
    std::string source = "npcap";
};

namespace
{
struct FlowKeyHasher
{
    std::size_t operator()(const FlowKey& key) const
    {
        std::size_t seed = 0;
        HashCombine(seed, static_cast<int>(key.protocol));
        HashCombine(seed, key.localAddress);
        HashCombine(seed, key.localPort);
        HashCombine(seed, key.remoteAddress);
        HashCombine(seed, key.remotePort);
        return seed;
    }
};

NetworkFlowEvent BuildFlowEvent(
    const FlowKey& key,
    const FlowState& state)
{
    NetworkFlowEvent event{};
    event.timestampStartQpc = state.timestampStartQpc;
    event.timestampLastQpc = state.timestampLastQpc;
    event.protocol = key.protocol;
    event.localAddress = key.localAddress;
    event.localPort = key.localPort;
    event.remoteAddress = key.remoteAddress;
    event.remotePort = key.remotePort;
    event.packetCount = state.packetCount;
    event.bytesTotal = state.bytesTotal;
    event.bytesIn = state.bytesIn;
    event.bytesOut = state.bytesOut;
    event.direction = state.direction;
    event.pid = state.pid;
    event.processImagePath = state.processImagePath;
    event.source = state.source;
    return event;
}
} // namespace

struct FlowAggregator::Impl
{
    explicit Impl(const uint64_t emitIntervalQpc)
        : m_emitIntervalQpc(emitIntervalQpc)
    {
    }

    void ObservePacket(const ObservedNetworkPacket& packet)
    {
        FlowKey key{};
        key.protocol = packet.protocol;
        key.localAddress = packet.localAddress;
        key.localPort = packet.localPort;
        key.remoteAddress = packet.remoteAddress;
        key.remotePort = packet.remotePort;

        auto [it, inserted] = m_flows.try_emplace(key);
        FlowState& state = it->second;
        if (inserted)
        {
            state.timestampStartQpc = packet.timestampQpc;
            state.source = packet.source;
        }

        state.timestampLastQpc = packet.timestampQpc;
        state.packetCount += 1;
        state.bytesTotal += packet.packetBytes;
        state.direction = packet.direction;
        state.pid = packet.pid;
        state.processImagePath = packet.processImagePath;
        state.source = packet.source;

        if (packet.direction == NetworkDirection::Inbound)
        {
            state.bytesIn += packet.packetBytes;
        }
        else if (packet.direction == NetworkDirection::Outbound)
        {
            state.bytesOut += packet.packetBytes;
        }
    }

    std::vector<NetworkFlowEvent> CollectReadyEvents(const uint64_t nowQpc)
    {
        std::vector<NetworkFlowEvent> readyEvents;

        for (auto it = m_flows.begin(); it != m_flows.end();)
        {
            const FlowState& state = it->second;
            const bool idle = nowQpc >= state.timestampLastQpc
                && nowQpc - state.timestampLastQpc >= m_emitIntervalQpc;
            const bool segmentReady = nowQpc >= state.timestampStartQpc
                && nowQpc - state.timestampStartQpc >= m_emitIntervalQpc;

            if (!idle && !segmentReady)
            {
                ++it;
                continue;
            }

            if (state.packetCount > 0)
            {
                readyEvents.push_back(BuildFlowEvent(it->first, state));
            }

            it = m_flows.erase(it);
        }

        return readyEvents;
    }

    std::vector<NetworkFlowEvent> FlushAll()
    {
        std::vector<NetworkFlowEvent> readyEvents;
        readyEvents.reserve(m_flows.size());

        for (const auto& [key, state] : m_flows)
        {
            if (state.packetCount == 0)
            {
                continue;
            }

            readyEvents.push_back(BuildFlowEvent(key, state));
        }

        m_flows.clear();
        return readyEvents;
    }

private:
    uint64_t m_emitIntervalQpc = 0;
    std::unordered_map<FlowKey, FlowState, FlowKeyHasher> m_flows;
};

FlowAggregator::FlowAggregator(const std::chrono::milliseconds flowIdlePeriod)
    : m_impl(std::make_unique<Impl>(MillisecondsToQpc(flowIdlePeriod)))
{
}

FlowAggregator::~FlowAggregator() = default;

void FlowAggregator::ObservePacket(const ObservedNetworkPacket& packet)
{
    m_impl->ObservePacket(packet);
}

std::vector<NetworkFlowEvent> FlowAggregator::CollectReadyEvents(const uint64_t nowQpc)
{
    return m_impl->CollectReadyEvents(nowQpc);
}

std::vector<NetworkFlowEvent> FlowAggregator::FlushAll()
{
    return m_impl->FlushAll();
}

uint64_t FlowAggregator::MillisecondsToQpc(const std::chrono::milliseconds value)
{
    return static_cast<uint64_t>(value.count()) * 1000ULL;
}
