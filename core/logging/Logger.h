#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "../config/AppConfig.h"
#include "../events/ProcessStartEvent.h"
#include "../guard/Guard.h"

class Logger
{
public:
    explicit Logger(const AppConfig& config);

    void LogRuntimeStart(const AppConfig& config);
    void LogRuntimeStop();
    void LogCollectorStart(bool success);
    void LogCollectorStop();
    void LogInfo(const std::wstring& category, const std::wstring& message);
    void LogProcessEvent(const ProcessStartEvent& event);
    void LogProcessAlerts(const ProcessStartEvent& event, const std::vector<Alert>& alerts);
    void LogDownloadCandidate(const std::wstring& path, const std::wstring& status);
    void LogStableDownloadCandidate(const std::wstring& path);
    void LogDownloadScanResult(const DownloadScanResult& result);

private:
    void WriteRecord(const std::string& category, const std::vector<std::pair<std::string, std::string>>& fields);
    void WriteConsoleLine(const std::wstring& line);

    bool m_consoleEnabled = true;
    bool m_fileEnabled = true;
    std::filesystem::path m_logFilePath;
    std::ofstream m_file;
    std::mutex m_mutex;
};
