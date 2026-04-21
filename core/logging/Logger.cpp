#include "Logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#if defined(_WIN32)
#define NOMINMAX
#include <Windows.h>
#else
#include <codecvt>
#include <locale>
#endif

namespace
{
std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

#if defined(_WIN32)
    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (required <= 0)
    {
        return {};
    }

    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);
    return result;
#else
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(value);
#endif
}

std::wstring BytesToWide(const std::string& value)
{
    return std::wstring(value.begin(), value.end());
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream output;
    for (const unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\':
            output << "\\\\";
            break;
        case '"':
            output << "\\\"";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (ch < 0x20)
            {
                output << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(ch)
                    << std::dec << std::setfill(' ');
            }
            else
            {
                output << static_cast<char>(ch);
            }
            break;
        }
    }

    return output.str();
}

std::string JsonStringField(const std::string& name, const std::string& value)
{
    return "\"" + name + "\":\"" + JsonEscape(value) + "\"";
}

std::string JsonBoolField(const std::string& name, bool value)
{
    return "\"" + name + "\":" + (value ? "true" : "false");
}

std::string JsonIntField(const std::string& name, long long value)
{
    return "\"" + name + "\":" + std::to_string(value);
}

std::string JsonRawNumberField(const std::string& name, const std::string& value)
{
    return "\"" + name + "\":" + value;
}

bool IsJsonBooleanField(const std::string& name)
{
    return name == "success"
        || name == "consoleLogging"
        || name == "fileLogging"
        || name == "virusTotalQueried";
}

bool IsJsonIntegerField(const std::string& name)
{
    return name == "pid"
        || name == "ppid"
        || name == "timestampQpc"
        || name == "alertCount"
        || name == "maliciousCount"
        || name == "suspiciousCount"
        || name == "downloadPollMs"
        || name == "downloadQuietMs";
}

bool IsUnsignedIntegerText(const std::string& value)
{
    return !value.empty()
        && value.find_first_not_of("0123456789") == std::string::npos;
}

std::string NowIsoUtc()
{
    const std::time_t now = std::time(nullptr);
    std::tm utc{};

#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif

    std::ostringstream stream;
    stream << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return stream.str();
}

std::string SeverityToString(const Severity severity)
{
    switch (severity)
    {
    case Severity::Info:
        return "info";
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    }

    return "unknown";
}

std::string DownloadScanOutcomeToString(const DownloadScanOutcome outcome)
{
    switch (outcome)
    {
    case DownloadScanOutcome::Clean:
        return "clean";
    case DownloadScanOutcome::Malicious:
        return "malicious";
    case DownloadScanOutcome::Unknown:
        return "unknown";
    case DownloadScanOutcome::Error:
        return "error";
    }

    return "unknown";
}
} // namespace

Logger::Logger(const AppConfig& config)
    : m_consoleEnabled(config.consoleLoggingEnabled),
      m_fileEnabled(config.fileLoggingEnabled),
      m_logFilePath(config.logFilePath)
{
    if (!m_fileEnabled)
    {
        return;
    }

    std::error_code ec;
    const auto parent = m_logFilePath.parent_path();
    if (!parent.empty())
    {
        std::filesystem::create_directories(parent, ec);
        if (ec)
        {
            m_fileEnabled = false;
            return;
        }
    }

    m_file.open(m_logFilePath, std::ios::out | std::ios::app);
    if (!m_file.is_open())
    {
        m_fileEnabled = false;
    }
}

void Logger::LogRuntimeStart(const AppConfig& config)
{
    WriteRecord(
        "runtime_start",
        {
            { "downloadPollMs", std::to_string(config.downloadPollInterval.count()) },
            { "downloadQuietMs", std::to_string(config.downloadQuietPeriod.count()) },
            { "consoleLogging", config.consoleLoggingEnabled ? "true" : "false" },
            { "fileLogging", config.fileLoggingEnabled ? "true" : "false" },
            { "logFile", config.logFilePath.string() }
        });
}

void Logger::LogRuntimeStop()
{
    WriteConsoleLine(L"Runtime stopped.");
    WriteRecord("runtime_stop", {});
}

void Logger::LogCollectorStart(bool success)
{
    WriteConsoleLine(success ? L"Collector started." : L"Failed to start EventCollector.");
    WriteRecord("collector_start", { { "success", success ? "true" : "false" } });
}

void Logger::LogCollectorStop()
{
    WriteConsoleLine(L"Collector stopped.");
    WriteRecord("collector_stop", {});
}

void Logger::LogInfo(const std::wstring& category, const std::wstring& message)
{
    WriteConsoleLine(message);
    WriteRecord(
        WideToUtf8(category),
        {
            { "message", WideToUtf8(message) }
        });
}

void Logger::LogProcessEvent(const ProcessStartEvent& event)
{
    WriteRecord(
        "process_event_received",
        {
            { "pid", std::to_string(event.pid) },
            { "ppid", std::to_string(event.ppid) },
            { "timestampQpc", std::to_string(event.timestampQpc) },
            { "imagePath", WideToUtf8(event.imagePath) },
            { "parentImagePath", WideToUtf8(event.parentImagePath) },
            { "commandLine", WideToUtf8(event.commandLine) }
        });
}

void Logger::LogProcessAlerts(const ProcessStartEvent& event, const std::vector<Alert>& alerts)
{
    std::wostringstream line;
    line << L"PID=" << event.pid
        << L" PPID=" << event.ppid
        << L" Image=" << (event.imagePath.empty() ? L"<empty>" : event.imagePath)
        << L" Alerts=" << alerts.size();

    if (!event.commandLine.empty())
    {
        line << L" CommandLine=" << event.commandLine;
    }

    WriteConsoleLine(line.str());

    WriteRecord(
        "process_alerts_produced",
        {
            { "pid", std::to_string(event.pid) },
            { "alertCount", std::to_string(alerts.size()) }
        });

    for (const Alert& alert : alerts)
    {
        WriteRecord(
            "process_alert",
            {
                { "pid", std::to_string(alert.pid) },
                { "severity", SeverityToString(alert.severity) },
                { "ruleName", WideToUtf8(alert.ruleName) },
                { "message", WideToUtf8(alert.message) }
            });
    }
}

void Logger::LogDownloadCandidate(const std::wstring& path, const std::wstring& status)
{
    WriteConsoleLine(L"Download candidate " + status + L": " + path);
    WriteRecord(
        "download_candidate",
        {
            { "path", WideToUtf8(path) },
            { "status", WideToUtf8(status) }
        });
}

void Logger::LogStableDownloadCandidate(const std::wstring& path)
{
    WriteConsoleLine(L"Forwarding stable download: " + path);
    WriteRecord(
        "download_candidate_stable",
        {
            { "path", WideToUtf8(path) }
        });
}

void Logger::LogDownloadScanResult(const DownloadScanResult& result)
{
    std::wostringstream line;
    line << L"Download scan result: " << result.path
        << L" outcome=" << BytesToWide(DownloadScanOutcomeToString(result.outcome))
        << L" status=" << result.status;
    WriteConsoleLine(line.str());

    WriteRecord(
        "download_scan_result",
        {
            { "path", WideToUtf8(result.path) },
            { "outcome", DownloadScanOutcomeToString(result.outcome) },
            { "sha256", result.sha256 },
            { "virusTotalQueried", result.virusTotalQueried ? "true" : "false" },
            { "status", WideToUtf8(result.status) },
            { "maliciousCount", std::to_string(result.maliciousCount) },
            { "suspiciousCount", std::to_string(result.suspiciousCount) }
        });
}

void Logger::WriteRecord(
    const std::string& category,
    const std::vector<std::pair<std::string, std::string>>& fields)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_fileEnabled || !m_file.is_open())
    {
        return;
    }

    m_file << "{"
        << JsonStringField("timestamp", NowIsoUtc())
        << "," << JsonStringField("category", category);

    for (const auto& [name, value] : fields)
    {
        if (IsJsonBooleanField(name) && (value == "true" || value == "false"))
        {
            m_file << "," << JsonBoolField(name, value == "true");
        }
        else if (IsJsonIntegerField(name) && IsUnsignedIntegerText(value))
        {
            m_file << "," << JsonRawNumberField(name, value);
        }
        else
        {
            m_file << "," << JsonStringField(name, value);
        }
    }

    m_file << "}\n";
    m_file.flush();
}

void Logger::WriteConsoleLine(const std::wstring& line)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_consoleEnabled)
    {
        std::wcout << line << L"\n";
    }
}
