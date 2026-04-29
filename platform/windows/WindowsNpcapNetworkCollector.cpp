#include "WindowsNpcapNetworkCollector.h"

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)

#include <winsock2.h>
#include <ws2tcpip.h>

#include <pcap.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>

namespace
{
constexpr int kEthernetHeaderLength = 14;
constexpr int kMinIpv4HeaderLength = 20;
constexpr int kMinTcpHeaderLength = 20;
constexpr int kMinUdpHeaderLength = 8;

bool CheckLimit(const pcap_pkthdr* packetHeader, const int start, const int amountToRead)
{
    if (!packetHeader || start < 0 || amountToRead < 0)
    {
        return false;
    }

    const int caplen = static_cast<int>(packetHeader->caplen);
    if (start > caplen || amountToRead > caplen)
    {
        return false;
    }

    return start <= caplen - amountToRead;
}

uint16_t ReadBigEndian16(const u_char* data, const int offset)
{
    return (static_cast<uint16_t>(data[offset]) << 8)
        | static_cast<uint16_t>(data[offset + 1]);
}

std::string FormatIpv4Address(const u_char* bytes)
{
    return std::to_string(static_cast<unsigned int>(bytes[0]))
        + "."
        + std::to_string(static_cast<unsigned int>(bytes[1]))
        + "."
        + std::to_string(static_cast<unsigned int>(bytes[2]))
        + "."
        + std::to_string(static_cast<unsigned int>(bytes[3]));
}

std::string SockaddrToIpv4String(const sockaddr* address)
{
    if (!address || address->sa_family != AF_INET)
    {
        return {};
    }

    const sockaddr_in* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (!InetNtopA(AF_INET, const_cast<in_addr*>(&ipv4->sin_addr), buffer.data(), static_cast<DWORD>(buffer.size())))
    {
        return {};
    }

    return buffer.data();
}

bool MatchesInterfacePreference(const AppConfig& config, const pcap_if_t* device)
{
    if (config.networkInterface.empty() || !device)
    {
        return false;
    }

    if (device->name && config.networkInterface == device->name)
    {
        return true;
    }

    return device->description && config.networkInterface == device->description;
}

bool HasIpv4Address(const pcap_if_t* device)
{
    if (!device)
    {
        return false;
    }

    for (const pcap_addr* address = device->addresses; address != nullptr; address = address->next)
    {
        if (address->addr && address->addr->sa_family == AF_INET)
        {
            return true;
        }
    }

    return false;
}

std::unordered_set<std::string> CollectIpv4Addresses(const pcap_if_t* device)
{
    std::unordered_set<std::string> addresses;
    if (!device)
    {
        return addresses;
    }

    for (const pcap_addr* address = device->addresses; address != nullptr; address = address->next)
    {
        const std::string text = SockaddrToIpv4String(address->addr);
        if (!text.empty())
        {
            addresses.insert(text);
        }
    }

    return addresses;
}
} // namespace

WindowsNpcapNetworkCollector::WindowsNpcapNetworkCollector(const AppConfig& config)
    : m_config(config),
      m_aggregator(config.networkFlowIdlePeriod)
{
}

WindowsNpcapNetworkCollector::~WindowsNpcapNetworkCollector()
{
    Stop();
}

bool WindowsNpcapNetworkCollector::Start(OnFlowEvent cb)
{
    if (m_running.load())
    {
        return true;
    }

    DeviceSelection selection{};
    if (!SelectInterface(selection))
    {
        return false;
    }

    if (!OpenCaptureHandle(selection.name))
    {
        return false;
    }

    m_onFlow = std::move(cb);
    m_interfaceName = std::move(selection.name);
    m_interfaceDescription = std::move(selection.description);
    m_localIpv4Addresses = std::move(selection.localIpv4Addresses);
    m_stopRequested.store(false);
    m_running.store(true);

    try
    {
        m_thread = std::thread(&WindowsNpcapNetworkCollector::Run, this);
    }
    catch (...)
    {
        m_running.store(false);
        m_onFlow = {};
        CloseCaptureHandle();
        return false;
    }

    return true;
}

void WindowsNpcapNetworkCollector::Stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    m_stopRequested.store(true);
    if (m_handle)
    {
        pcap_breakloop(m_handle);
    }

    if (m_thread.joinable())
    {
        m_thread.join();
    }

    CloseCaptureHandle();
    m_onFlow = {};
    m_interfaceName.clear();
    m_interfaceDescription.clear();
    m_localIpv4Addresses.clear();
}

void WindowsNpcapNetworkCollector::PacketCallback(
    u_char* user,
    const pcap_pkthdr* header,
    const u_char* data)
{
    auto* self = reinterpret_cast<WindowsNpcapNetworkCollector*>(user);
    if (!self || !self->IsRunning())
    {
        return;
    }

    self->HandlePacket(header, data);
}

uint64_t WindowsNpcapNetworkCollector::NowQpc()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool WindowsNpcapNetworkCollector::SelectInterface(DeviceSelection& selection)
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errbuf) == -1 || !devices)
    {
        return false;
    }

    const pcap_if_t* chosen = nullptr;

    for (const pcap_if_t* device = devices; device != nullptr; device = device->next)
    {
        if (MatchesInterfacePreference(m_config, device))
        {
            chosen = device;
            break;
        }
    }

    if (!chosen && m_config.networkInterface.empty())
    {
        for (const pcap_if_t* device = devices; device != nullptr; device = device->next)
        {
            if ((device->flags & PCAP_IF_LOOPBACK) == 0 && HasIpv4Address(device))
            {
                chosen = device;
                break;
            }
        }
    }

    if (!chosen)
    {
        for (const pcap_if_t* device = devices; device != nullptr; device = device->next)
        {
            if (HasIpv4Address(device))
            {
                chosen = device;
                break;
            }
        }
    }

    if (!chosen)
    {
        chosen = devices;
    }

    if (chosen && chosen->name)
    {
        selection.name = chosen->name;
        selection.description = chosen->description ? chosen->description : chosen->name;
        selection.localIpv4Addresses = CollectIpv4Addresses(chosen);
    }

    pcap_freealldevs(devices);
    return !selection.name.empty();
}

bool WindowsNpcapNetworkCollector::OpenCaptureHandle(const std::string& interfaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE]{};
    m_handle = pcap_open_live(interfaceName.c_str(), 65535, 0, 250, errbuf);
    if (!m_handle)
    {
        return false;
    }

    if (pcap_setnonblock(m_handle, 1, errbuf) != 0)
    {
        CloseCaptureHandle();
        return false;
    }

    return true;
}

void WindowsNpcapNetworkCollector::CloseCaptureHandle()
{
    if (m_handle)
    {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}

void WindowsNpcapNetworkCollector::Run()
{
    while (!m_stopRequested.load())
    {
        const int dispatchResult = pcap_dispatch(
            m_handle,
            64,
            &WindowsNpcapNetworkCollector::PacketCallback,
            reinterpret_cast<u_char*>(this));

        if (dispatchResult == PCAP_ERROR_BREAK)
        {
            break;
        }

        if (dispatchResult < 0)
        {
            break;
        }

        EmitReadyFlows(NowQpc());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EmitFinalFlows();
}

void WindowsNpcapNetworkCollector::HandlePacket(const pcap_pkthdr* header, const u_char* data)
{
    ParsedIpv4Packet packet{};
    if (!TryParsePacket(header, data, packet))
    {
        return;
    }

    ObservedNetworkPacket observed{};
    if (!NormalizePacket(packet, observed))
    {
        return;
    }

    m_aggregator.ObservePacket(observed);
}

void WindowsNpcapNetworkCollector::EmitReadyFlows(const uint64_t nowQpc)
{
    if (!m_onFlow)
    {
        return;
    }

    for (NetworkFlowEvent& event : m_aggregator.CollectReadyEvents(nowQpc))
    {
        m_onFlow(std::move(event));
    }
}

void WindowsNpcapNetworkCollector::EmitFinalFlows()
{
    if (!m_onFlow)
    {
        return;
    }

    for (NetworkFlowEvent& event : m_aggregator.FlushAll())
    {
        m_onFlow(std::move(event));
    }
}

bool WindowsNpcapNetworkCollector::TryParsePacket(
    const pcap_pkthdr* header,
    const u_char* data,
    ParsedIpv4Packet& packet) const
{
    if (!CheckLimit(header, 0, kEthernetHeaderLength))
    {
        return false;
    }

    const uint16_t etherType = ReadBigEndian16(data, 12);
    if (etherType != 0x0800)
    {
        return false;
    }

    const int ipv4Offset = kEthernetHeaderLength;
    if (!CheckLimit(header, ipv4Offset, kMinIpv4HeaderLength))
    {
        return false;
    }

    const uint8_t versionAndHeaderLength = data[ipv4Offset];
    const uint8_t version = static_cast<uint8_t>(versionAndHeaderLength >> 4);
    const uint8_t ipv4HeaderLength = static_cast<uint8_t>((versionAndHeaderLength & 0x0F) * 4);
    if (version != 4 || ipv4HeaderLength < kMinIpv4HeaderLength)
    {
        return false;
    }

    if (!CheckLimit(header, ipv4Offset, ipv4HeaderLength))
    {
        return false;
    }

    const uint8_t protocol = data[ipv4Offset + 9];
    if (protocol != 6 && protocol != 17)
    {
        return false;
    }

    const int l4Offset = ipv4Offset + ipv4HeaderLength;
    if (protocol == 6)
    {
        if (!CheckLimit(header, l4Offset, kMinTcpHeaderLength))
        {
            return false;
        }

        const uint8_t tcpHeaderLength = static_cast<uint8_t>(((data[l4Offset + 12] >> 4) & 0x0F) * 4);
        if (tcpHeaderLength < kMinTcpHeaderLength || !CheckLimit(header, l4Offset, tcpHeaderLength))
        {
            return false;
        }

        packet.protocol = NetworkProtocol::Tcp;
        packet.srcPort = ReadBigEndian16(data, l4Offset);
        packet.dstPort = ReadBigEndian16(data, l4Offset + 2);
    }
    else
    {
        if (!CheckLimit(header, l4Offset, kMinUdpHeaderLength))
        {
            return false;
        }

        const uint16_t udpLength = ReadBigEndian16(data, l4Offset + 4);
        if (udpLength < kMinUdpHeaderLength)
        {
            return false;
        }

        packet.protocol = NetworkProtocol::Udp;
        packet.srcPort = ReadBigEndian16(data, l4Offset);
        packet.dstPort = ReadBigEndian16(data, l4Offset + 2);
    }

    packet.srcAddress = FormatIpv4Address(data + ipv4Offset + 12);
    packet.dstAddress = FormatIpv4Address(data + ipv4Offset + 16);
    packet.packetBytes = header ? static_cast<uint64_t>(header->len) : 0;
    return true;
}

bool WindowsNpcapNetworkCollector::NormalizePacket(
    const ParsedIpv4Packet& packet,
    ObservedNetworkPacket& observed) const
{
    observed.timestampQpc = NowQpc();
    observed.protocol = packet.protocol;
    observed.packetBytes = packet.packetBytes;
    observed.source = "npcap";

    const bool srcIsLocal = m_localIpv4Addresses.find(packet.srcAddress) != m_localIpv4Addresses.end();
    const bool dstIsLocal = m_localIpv4Addresses.find(packet.dstAddress) != m_localIpv4Addresses.end();

    if (srcIsLocal && !dstIsLocal)
    {
        observed.direction = NetworkDirection::Outbound;
        observed.localAddress = packet.srcAddress;
        observed.localPort = packet.srcPort;
        observed.remoteAddress = packet.dstAddress;
        observed.remotePort = packet.dstPort;
        return true;
    }

    if (dstIsLocal && !srcIsLocal)
    {
        observed.direction = NetworkDirection::Inbound;
        observed.localAddress = packet.dstAddress;
        observed.localPort = packet.dstPort;
        observed.remoteAddress = packet.srcAddress;
        observed.remotePort = packet.srcPort;
        return true;
    }

    observed.direction = NetworkDirection::Unknown;
    observed.localAddress = packet.srcAddress;
    observed.localPort = packet.srcPort;
    observed.remoteAddress = packet.dstAddress;
    observed.remotePort = packet.dstPort;
    return true;
}

#endif
