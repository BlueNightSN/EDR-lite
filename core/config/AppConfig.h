#pragma once

#include <cstddef>
#include <chrono>
#include <filesystem>
#include <string>

struct AppConfig
{
    std::chrono::milliseconds downloadPollInterval{ 500 };
    std::chrono::milliseconds downloadQuietPeriod{ 2000 };
    bool networkEnabled = false;
    std::chrono::milliseconds networkFlowIdlePeriod{ 5000 };
    std::size_t networkMaxEventsPerTick = 32;
    std::size_t networkMaxQueueSize = 2048;
    std::string networkInterface;
    bool consoleLoggingEnabled = true;
    bool fileLoggingEnabled = true;
    std::filesystem::path logFilePath{ "logs/edr-lite.jsonl" };
};

AppConfig LoadAppConfigFromEnvironment();
