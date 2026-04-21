#include "Runtime.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cwctype>
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
#include <Windows.h>
#endif

#include "DownloadCandidateTracker.h"
#include "../core/collectors/EventCollectorFactory.h"
#include "../core/config/AppConfig.h"
#include "../core/guard/Guard.h"
#include "../core/logging/Logger.h"
#include "../core/process/ProcessTracker.h"

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
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> stopRequested{ false };

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
        bool hasProcessEvent = false;
        bool shouldStop = false;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait_for(lock, config.downloadPollInterval, [&]()
                {
                    return !processQueue.empty()
                        || !downloadQueue.empty()
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

            shouldStop = stopRequested.load() && processQueue.empty();
            shouldStop = shouldStop && downloadQueue.empty();
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

        if (shouldStop)
        {
            break;
        }
    }

    collector->Stop();
    logger.LogCollectorStop();

    if (inputThread.joinable())
    {
        inputThread.join();
    }

    logger.LogRuntimeStop();
    return 0;
}
