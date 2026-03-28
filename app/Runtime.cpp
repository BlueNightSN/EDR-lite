#include "Runtime.h"

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>

#include "../core/collectors/EventCollectorFactory.h"
#include "../core/guard/Guard.h"

namespace
{
void PrintProcessEvent(const ProcessStartEvent& event, std::size_t alertCount)
{
    std::wcout << L"PID=" << event.pid
        << L" PPID=" << event.ppid
        << L" Image=" << (event.imagePath.empty() ? L"<empty>" : event.imagePath)
        << L" Alerts=" << alertCount
        << L"\n";
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
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::atomic<bool> stopRequested{ false };

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

    std::thread inputThread([&]()
        {
            std::wstring dummy;
            std::getline(std::wcin, dummy);

            stopRequested.store(true);
            queueCv.notify_all();
        });

    while (true)
    {
        ProcessStartEvent event{};

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait(lock, [&]()
                {
                    return !eventQueue.empty() || stopRequested.load();
                });

            if (eventQueue.empty())
            {
                if (stopRequested.load())
                {
                    break;
                }

                continue;
            }

            event = std::move(eventQueue.front());
            eventQueue.pop();
        }

        const auto alerts = guard.Inspect(event);
        PrintProcessEvent(event, alerts.size());
    }

    collector->Stop();

    if (inputThread.joinable())
    {
        inputThread.join();
    }

    return 0;
}
