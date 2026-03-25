#include <iostream>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>

#include "EventCollectorFactory.h"
#include "Guard.h"
void PrintProcessEvent(const ProcessStartEvent& e, std::size_t alertCount);

int main()
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
        [&](const ProcessStartEvent& e)
        {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                eventQueue.push(e);
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
        ProcessStartEvent e{};

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

            e = std::move(eventQueue.front());
            eventQueue.pop();
        }
        
        const auto alerts = guard.Inspect(e);
        PrintProcessEvent(e, alerts.size());
    }

    collector->Stop();

    if (inputThread.joinable())
    {
        inputThread.join();
    }

    return 0;
}
void PrintProcessEvent(const ProcessStartEvent& e, std::size_t alertCount)
{
    std::wcout << L"PID=" << e.pid
        << L" PPID=" << e.ppid
        << L" Image=" << (e.imagePath.empty() ? L"<empty>" : e.imagePath)
        << L" Alerts=" << alertCount
        << L"\n";
}
