#pragma once

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_set>

#include "../../core/config/AppConfig.h"
#include "../../core/events/NetworkFlowEvent.h"
#include "../../core/network/FlowAggregator.h"

struct pcap;
using pcap_t = struct pcap;
struct pcap_if;
using pcap_if_t = struct pcap_if;
struct pcap_pkthdr;
using u_char = unsigned char;

class WindowsNpcapNetworkCollector
{
public:
    using OnFlowEvent = std::function<bool(NetworkFlowEvent&&)>;

    explicit WindowsNpcapNetworkCollector(const AppConfig& config);
    ~WindowsNpcapNetworkCollector();

    WindowsNpcapNetworkCollector(const WindowsNpcapNetworkCollector&) = delete;
    WindowsNpcapNetworkCollector& operator=(const WindowsNpcapNetworkCollector&) = delete;
    WindowsNpcapNetworkCollector(WindowsNpcapNetworkCollector&&) = delete;
    WindowsNpcapNetworkCollector& operator=(WindowsNpcapNetworkCollector&&) = delete;

    bool Start(OnFlowEvent cb);
    void Stop();
    bool IsRunning() const { return m_running.load(); }

private:
    struct DeviceSelection
    {
        std::string name;
        std::string description;
        std::unordered_set<std::string> localIpv4Addresses;
    };

    struct ParsedIpv4Packet
    {
        NetworkProtocol protocol = NetworkProtocol::Tcp;
        std::string srcAddress;
        uint16_t srcPort = 0;
        std::string dstAddress;
        uint16_t dstPort = 0;
        uint64_t packetBytes = 0;
    };

    static void PacketCallback(u_char* user, const pcap_pkthdr* header, const u_char* data);
    static uint64_t NowQpc();

    bool SelectInterface(DeviceSelection& selection);
    bool OpenCaptureHandle(const std::string& interfaceName);
    void CloseCaptureHandle();
    void Run();
    void HandlePacket(const pcap_pkthdr* header, const u_char* data);
    void EmitReadyFlows(uint64_t nowQpc);
    void EmitFinalFlows();
    bool TryParsePacket(const pcap_pkthdr* header, const u_char* data, ParsedIpv4Packet& packet) const;
    bool NormalizePacket(const ParsedIpv4Packet& packet, ObservedNetworkPacket& observed) const;

    AppConfig m_config;
    FlowAggregator m_aggregator;
    std::thread m_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_stopRequested{ false };
    pcap_t* m_handle = nullptr;
    OnFlowEvent m_onFlow;
    std::string m_interfaceName;
    std::string m_interfaceDescription;
    std::unordered_set<std::string> m_localIpv4Addresses;
};

#endif
