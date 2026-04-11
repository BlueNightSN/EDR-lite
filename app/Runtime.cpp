#include "Runtime.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#if defined(_WIN32)
#include <Windows.h>
#endif

#include "../core/collectors/EventCollectorFactory.h"
#include "../core/guard/Guard.h"

namespace
{
constexpr auto kDownloadCandidateTick = std::chrono::milliseconds(500);
constexpr auto kDownloadQuietPeriod = std::chrono::seconds(2);

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct DownloadCandidate
{
    std::wstring path;
    TimePoint firstSeen;
    TimePoint lastChangeTime;
    uintmax_t lastObservedSize = 0;
    uintmax_t previousObservedSize = 0;
    bool hasObservedSize = false;
};

std::wstring NormalizePathKey(const std::wstring& path)
{
    if (path.empty())
    {
        return {};
    }

    std::filesystem::path normalized(path);
    normalized = normalized.lexically_normal();
    normalized.make_preferred();
    return normalized.wstring();
}

void PrintProcessEvent(const ProcessStartEvent& event, std::size_t alertCount)
{
    std::wcout << L"PID=" << event.pid
        << L" PPID=" << event.ppid
        << L" Image=" << (event.imagePath.empty() ? L"<empty>" : event.imagePath)
        << L" Alerts=" << alertCount
        << L"\n";
}

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

void RegisterDownloadActivity(
    std::unordered_map<std::wstring, DownloadCandidate>& candidates,
    const DownloadFileEvent& event,
    const TimePoint now)
{
    const std::wstring key = NormalizePathKey(event.path);
    if (key.empty())
    {
        return;
    }

    auto [it, inserted] = candidates.try_emplace(key);
    DownloadCandidate& candidate = it->second;

    if (inserted)
    {
        candidate.path = key;
        candidate.firstSeen = now;
        std::wcout << L"New download candidate: " << key << L"\n";
    }
    else
    {
        std::wcout << L"Updated download candidate: " << key << L"\n";
    }

    candidate.lastChangeTime = now;
}

void ForwardStableDownloadCandidates(
    std::unordered_map<std::wstring, DownloadCandidate>& candidates,
    Guard& guard,
    const TimePoint now)
{
    std::error_code ec;

    for (auto it = candidates.begin(); it != candidates.end();)
    {
        DownloadCandidate& candidate = it->second;
        const std::filesystem::path path(candidate.path);

        if (!std::filesystem::exists(path, ec) || ec)
        {
            ec.clear();
            it = candidates.erase(it);
            continue;
        }

        const auto status = std::filesystem::status(path, ec);
        if (ec || !std::filesystem::is_regular_file(status))
        {
            ec.clear();
            it = candidates.erase(it);
            continue;
        }

        const uintmax_t currentSize = std::filesystem::file_size(path, ec);
        if (ec)
        {
            ec.clear();
            ++it;
            continue;
        }

        if (!candidate.hasObservedSize)
        {
            candidate.lastObservedSize = currentSize;
            candidate.previousObservedSize = currentSize;
            candidate.hasObservedSize = true;
            ++it;
            continue;
        }

        candidate.previousObservedSize = candidate.lastObservedSize;
        candidate.lastObservedSize = currentSize;

        if (candidate.lastObservedSize != candidate.previousObservedSize)
        {
            candidate.lastChangeTime = now;
            std::wcout << L"Size changed for candidate: " << candidate.path << L"\n";
            ++it;
            continue;
        }

        if (now - candidate.lastChangeTime < kDownloadQuietPeriod)
        {
            ++it;
            continue;
        }

        std::wcout << L"Forwarding stable download: " << candidate.path << L"\n";
        guard.InspectDownloadPath(candidate.path);
        it = candidates.erase(it);
    }
}
} // namespace

int RunApplication()
{
    std::unique_ptr<IEventCollector> collector = CreateEventCollector();
    Guard guard;

    if (!collector)
    {
        std::wcerr << L"No supported EventCollector backend is available for this platform.\n";
        return 1;
    }

    std::queue<ProcessStartEvent> eventQueue;
    // std::queue<DownloadFileEvent> downloadQueue;
    // std::unordered_map<std::wstring, DownloadCandidate> downloadCandidates;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> stopRequested{ false };

    // collector->SetOnDownloadActivity(
    //     [&](const DownloadFileEvent& event)
    //     {
    //         {
    //             std::lock_guard<std::mutex> lock(queueMutex);
    //             downloadQueue.push(event);
    //         }
    //
    //         queueCv.notify_one();
    //     });

    const bool started = collector->Start(
        [&](const ProcessStartEvent& event)
        {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                eventQueue.push(event);
            }

            queueCv.notify_one();
        });

    if (!started)
    {
        std::wcerr << L"Failed to start EventCollector.\n";
        return 1;
    }

    std::wcout << L"Running... open notepad/calc/cmd. Press Enter to stop.\n";

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
        std::wcout << L"No interactive console input is attached; stop the app from the debugger or by closing the process.\n";
    }

    while (true)
    {
        // std::queue<DownloadFileEvent> pendingDownloads;
        ProcessStartEvent event{};
        bool hasProcessEvent = false;
        bool shouldStop = false;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait_for(lock, kDownloadCandidateTick, [&]()
                {
                    return !eventQueue.empty()
                        // || !downloadQueue.empty()
                        || stopRequested.load();
                });

            // while (!downloadQueue.empty())
            // {
            //     pendingDownloads.push(std::move(downloadQueue.front()));
            //     downloadQueue.pop();
            // }

            if (!eventQueue.empty())
            {
                event = std::move(eventQueue.front());
                eventQueue.pop();
                hasProcessEvent = true;
            }

            shouldStop = stopRequested.load() && eventQueue.empty();
            // && downloadQueue.empty();
        }

        // const TimePoint now = Clock::now();

        // while (!pendingDownloads.empty())
        // {
        //     RegisterDownloadActivity(downloadCandidates, pendingDownloads.front(), now);
        //     pendingDownloads.pop();
        // }
        //
        // ForwardStableDownloadCandidates(downloadCandidates, guard, now);

        if (hasProcessEvent)
        {
            const auto alerts = guard.Inspect(event);
            PrintProcessEvent(event, alerts.size());
        }

        if (shouldStop)
        {
            break;
        }
    }

    collector->Stop();

    if (inputThread.joinable())
    {
        inputThread.join();
    }

    return 0;
}
