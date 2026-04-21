#pragma once

#include <chrono>
#include <filesystem>

struct AppConfig
{
    std::chrono::milliseconds downloadPollInterval{ 500 };
    std::chrono::milliseconds downloadQuietPeriod{ 2000 };
    bool consoleLoggingEnabled = true;
    bool fileLoggingEnabled = true;
    std::filesystem::path logFilePath{ "logs/edr-lite.jsonl" };
};

AppConfig LoadAppConfigFromEnvironment();

