#include <iostream>
#include <algorithm>
#include "EventCollector.h"

int wmain()
{
    EventCollector collector;

    const bool started = collector.Start([](const ProcessStartEvent& e) {

        const size_t wrapWidth = 100;

        std::wcout << L"????????????????????????????????????????????????????????????\n";
        std::wcout << L"ProcessStart\n";
        std::wcout << L"  PID:  " << e.pid << L"\n";
        std::wcout << L"  PPID: " << e.ppid << L"\n";
        std::wcout << L"  TS:   " << e.timestampQpc << L"\n";

        // Image
        std::wcout << L"  Image: ";
        if (e.imagePath.empty())
        {
            std::wcout << L"<empty>\n";
        }
        else
        {
            std::wcout << e.imagePath << L"\n";
        }

        // Command line (wrapped)
        std::wcout << L"  Cmd:   ";
        if (e.commandLine.empty())
        {
            std::wcout << L"<empty>\n";
        }
        else
        {
            const std::wstring& cmd = e.commandLine;

            size_t firstMax = wrapWidth - 9; // 9 = length of "  Cmd:   "
            std::wcout << cmd.substr(0, firstMax) << L"\n";

            for (size_t pos = firstMax; pos < cmd.size(); )
            {
                size_t chunk = (std::min)(wrapWidth, cmd.size() - pos);
                std::wcout << L"          "  // indentation
                    << cmd.substr(pos, chunk)
                    << L"\n";
                pos += chunk;
            }
        }

        std::wcout << L"????????????????????????????????????????????????????????????\n\n";
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