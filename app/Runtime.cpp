#include "Runtime.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <Windows.h>
#endif

#include "DownloadCandidateTracker.h"
#include "../core/collectors/EventCollectorFactory.h"
#include "../core/config/AppConfig.h"
#include "../core/events/NetworkFlowEvent.h"
#include "../core/guard/Guard.h"
#include "../core/logging/Logger.h"
#include "../core/process/ProcessTracker.h"

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)
#include "../platform/windows/WindowsNpcapNetworkCollector.h"
#endif

namespace
{
bool HasInteractiveConsoleInput()
{
#if defined(_WIN32)
    HANDLE inputHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (inputHandle == nullptr || inputHandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD consoleMode = 0;
    return GetConsoleMode(inputHandle, &consoleMode) != 0;
#else
    return true;
#endif
}

#if defined(_WIN32)
std::wstring ReadProcessImagePathFallback(uint32_t pid)
{
    if (pid == 0)
    {
        return {};
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle)
    {
        return {};
    }

    std::wstring imagePath;
    DWORD bufferLength = MAX_PATH;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(bufferLength));

    while (true)
    {
        DWORD length = bufferLength;
        if (QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &length))
        {
            imagePath.assign(buffer.data(), buffer.data() + length);
            break;
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            break;
        }

        bufferLength *= 2;
        buffer.resize(static_cast<std::size_t>(bufferLength));
    }

    CloseHandle(processHandle);
    return imagePath;
}

void EnrichProcessImagePaths(ProcessStartEvent& event)
{
    if (event.imagePath.empty())
    {
        event.imagePath = ReadProcessImagePathFallback(event.pid);
    }

    if (event.parentImagePath.empty() && event.ppid != 0)
    {
        event.parentImagePath = ReadProcessImagePathFallback(event.ppid);
    }
}

bool EqualsInsensitive(const std::wstring& lhs, const std::wstring& rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        if (std::towlower(lhs[i]) != std::towlower(rhs[i]))
        {
            return false;
        }
    }

    return true;
}

bool IsOwnProcessEvent(const ProcessStartEvent& event)
{
    if (event.imagePath.empty())
    {
        return false;
    }

    const std::wstring filename = std::filesystem::path(event.imagePath).filename().wstring();
    return EqualsInsensitive(filename, L"EDR-lite.exe");
}
#endif

bool ShouldFlushDropWarning(
    const std::chrono::steady_clock::time_point lastWarning,
    const bool force)
{
    if (force)
    {
        return true;
    }

    if (lastWarning == std::chrono::steady_clock::time_point{})
    {
        return true;
    }

    return std::chrono::steady_clock::now() - lastWarning >= std::chrono::seconds(5);
}
} // namespace

int RunApplication()
{
    const AppConfig config = LoadAppConfigFromEnvironment();
    Logger logger(config);
    logger.LogRuntimeStart(config);

    std::unique_ptr<IEventCollector> collector = CreateEventCollector();
    Guard guard;
    ProcessTracker processTracker;
    DownloadCandidateTracker downloadTracker(config);

    if (!collector)
    {
        logger.LogInfo(
            L"runtime_error",
            L"No supported EventCollector backend is available for this platform.");
        logger.LogRuntimeStop();
        return 1;
    }

    guard.SetOnDownloadScanResult(
        [&](const DownloadScanResult& result)
        {
            logger.LogDownloadScanResult(result);
        });

    std::queue<ProcessStartEvent> processQueue;
    std::queue<DownloadFileEvent> downloadQueue;
    std::deque<NetworkFlowEvent> networkQueue;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> stopRequested{ false };
    bool collectorsStopped = false;
    bool collectorStopLogged = false;
    bool networkCollectorStopLogged = false;
    uint64_t pendingDroppedNetworkEvents = 0;
    std::chrono::steady_clock::time_point lastNetworkDropLog{};

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)
    std::unique_ptr<WindowsNpcapNetworkCollector> networkCollector;
    bool networkCollectorStarted = false;
#endif

    collector->SetOnDownloadActivity(
        [&](const DownloadFileEvent& event)
        {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                downloadQueue.push(event);
            }

            queueCv.notify_one();
        });

    const bool started = collector->Start(
        [&](const ProcessStartEvent& event)
        {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                processQueue.push(event);
            }

            queueCv.notify_one();
        });

    logger.LogCollectorStart(started);
    if (!started)
    {
        logger.LogRuntimeStop();
        return 1;
    }

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)
    if (config.networkEnabled)
    {
        networkCollector = std::make_unique<WindowsNpcapNetworkCollector>(config);
        networkCollectorStarted = networkCollector->Start(
            [&](NetworkFlowEvent&& event)
            {
                bool enqueued = false;
                bool shouldLogPressure = false;
                std::size_t queueSize = 0;
                uint64_t droppedCountToLog = 0;

                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    if (networkQueue.size() < config.networkMaxQueueSize)
                    {
                        networkQueue.push_back(std::move(event));
                        enqueued = true;
                    }
                    else
                    {
                        ++pendingDroppedNetworkEvents;
                        queueSize = networkQueue.size();

                        if (ShouldFlushDropWarning(lastNetworkDropLog, false))
                        {
                            shouldLogPressure = true;
                            droppedCountToLog = pendingDroppedNetworkEvents;
                            pendingDroppedNetworkEvents = 0;
                            lastNetworkDropLog = std::chrono::steady_clock::now();
                        }
                    }
                }

                if (enqueued)
                {
                    queueCv.notify_one();
                    return true;
                }

                if (shouldLogPressure)
                {
                    logger.LogNetworkQueuePressure(queueSize, droppedCountToLog);
                }

                return false;
            });

        if (networkCollectorStarted)
        {
            logger.LogInfo(L"network_collector", L"Optional Npcap network telemetry collector started.");
        }
        else
        {
            logger.LogInfo(L"network_collector", L"Optional Npcap network telemetry collector could not be started.");
            networkCollector.reset();
        }
    }
#elif defined(_WIN32)
    if (config.networkEnabled)
    {
        logger.LogInfo(
            L"network_collector",
            L"Network telemetry is enabled in config, but this build does not include optional Npcap support.");
    }
#endif

    logger.LogInfo(L"runtime_status", L"Running... open notepad/calc/cmd. Press Enter to stop.");

    std::thread inputThread;
    if (HasInteractiveConsoleInput())
    {
        inputThread = std::thread([&]()
            {
                std::wstring dummy;
                std::getline(std::wcin, dummy);

                stopRequested.store(true);
                queueCv.notify_all();
            });
    }
    else
    {
        logger.LogInfo(
            L"runtime_status",
            L"No interactive console input is attached; stop the app from the debugger or by closing the process.");
    }

    while (true)
    {
        std::queue<DownloadFileEvent> pendingDownloads;
        ProcessStartEvent processEvent{};
        std::vector<NetworkFlowEvent> pendingNetworkEvents;
        bool hasProcessEvent = false;
        bool shouldStopCollectors = false;
        bool shouldStop = false;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait_for(lock, config.downloadPollInterval, [&]()
                {
                    return !processQueue.empty()
                        || !downloadQueue.empty()
                        || !networkQueue.empty()
                        || stopRequested.load();
                });

            while (!downloadQueue.empty())
            {
                pendingDownloads.push(std::move(downloadQueue.front()));
                downloadQueue.pop();
            }

            if (!processQueue.empty())
            {
                processEvent = std::move(processQueue.front());
                processQueue.pop();
                hasProcessEvent = true;
            }

            const std::size_t networkEventsToDrain =
                config.networkMaxEventsPerTick < networkQueue.size()
                    ? config.networkMaxEventsPerTick
                    : networkQueue.size();
            pendingNetworkEvents.reserve(networkEventsToDrain);

            for (std::size_t i = 0; i < networkEventsToDrain; ++i)
            {
                pendingNetworkEvents.push_back(std::move(networkQueue.front()));
                networkQueue.pop_front();
            }

            shouldStopCollectors = stopRequested.load() && !collectorsStopped;
            shouldStop = stopRequested.load()
                && collectorsStopped
                && processQueue.empty()
                && downloadQueue.empty()
                && networkQueue.empty();
        }

        if (shouldStopCollectors)
        {
            collector->Stop();
            collectorsStopped = true;

            if (!collectorStopLogged)
            {
                logger.LogCollectorStop();
                collectorStopLogged = true;
            }

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)
            if (networkCollectorStarted && networkCollector)
            {
                networkCollector->Stop();
                if (!networkCollectorStopLogged)
                {
                    logger.LogInfo(L"network_collector", L"Optional Npcap network telemetry collector stopped.");
                    networkCollectorStopLogged = true;
                }
            }
#endif
        }

        while (!pendingDownloads.empty())
        {
            downloadTracker.ObserveDownloadActivity(pendingDownloads.front(), logger);
            pendingDownloads.pop();
        }

        for (const std::wstring& stablePath : downloadTracker.CollectStableCandidates(logger))
        {
            guard.InspectDownloadPath(stablePath);
        }

        if (hasProcessEvent)
        {
            bool skipProcessEvent = false;

#if defined(_WIN32)
            EnrichProcessImagePaths(processEvent);
            skipProcessEvent = IsOwnProcessEvent(processEvent);
#endif
            if (!skipProcessEvent)
            {
                processTracker.ObserveProcessStart(processEvent);
                logger.LogProcessEvent(processEvent);

                const auto alerts = guard.Inspect(processEvent);
                logger.LogProcessAlerts(processEvent, alerts);
            }
        }

        for (const NetworkFlowEvent& event : pendingNetworkEvents)
        {
            logger.LogNetworkFlowEvent(event);
        }

        if (shouldStop)
        {
            break;
        }
    }

    if (!collectorStopLogged)
    {
        collector->Stop();
        logger.LogCollectorStop();
    }

#if defined(_WIN32) && defined(EDR_LITE_HAS_NPCAP)
    if (networkCollectorStarted && networkCollector)
    {
        networkCollector->Stop();
        if (!networkCollectorStopLogged)
        {
            logger.LogInfo(L"network_collector", L"Optional Npcap network telemetry collector stopped.");
        }
    }
#endif

    {
        std::size_t queueSize = 0;
        uint64_t droppedCountToLog = 0;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (pendingDroppedNetworkEvents > 0 && ShouldFlushDropWarning(lastNetworkDropLog, true))
            {
                queueSize = networkQueue.size();
                droppedCountToLog = pendingDroppedNetworkEvents;
                pendingDroppedNetworkEvents = 0;
                lastNetworkDropLog = std::chrono::steady_clock::now();
            }
        }

        if (droppedCountToLog > 0)
        {
            logger.LogNetworkQueuePressure(queueSize, droppedCountToLog);
        }
    }

    if (inputThread.joinable())
    {
        inputThread.join();
    }

    logger.LogRuntimeStop();
    return 0;
}
