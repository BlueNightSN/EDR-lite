#include <iostream>
#include "EventCollector.h"

int wmain()
{
    EventCollector collector;

    const bool started = collector.Start([](const ProcessStartEvent& e) {
        std::wcout << L"[ProcessStart] PID=" << e.pid
            << L" PPID=" << e.ppid
            << L" TS=" << e.timestampQpc
            << L"\n";
        });

    if (!started)
    {
        std::wcerr << L"Failed to start EventCollector.\n";
        return 1;
    }

    std::wcout << L"Running... open notepad/calc/cmd. Press Enter to stop.\n";
    std::wstring dummy;
    std::getline(std::wcin, dummy);

    collector.Stop();
    return 0;
}