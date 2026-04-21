#include "AppConfig.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>

namespace
{
std::string ReadEnvironmentVariable(const char* name)
{
#if defined(_WIN32)
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr || length == 0)
    {
        return {};
    }

    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
#endif
}

std::string ToLowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch)
        {
            return static_cast<char>(std::tolower(ch));
        });
    return value;
}

bool TryParseBool(const std::string& raw, bool& value)
{
    const std::string text = ToLowerCopy(raw);
    if (text == "1" || text == "true" || text == "yes" || text == "on")
    {
        value = true;
        return true;
    }

    if (text == "0" || text == "false" || text == "no" || text == "off")
    {
        value = false;
        return true;
    }

    return false;
}

bool TryParseMilliseconds(const std::string& raw, std::chrono::milliseconds& value)
{
    try
    {
        const long long parsed = std::stoll(raw);
        if (parsed <= 0)
        {
            return false;
        }

        value = std::chrono::milliseconds(parsed);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void ApplyMillisecondsOverride(
    const char* name,
    std::chrono::milliseconds& target)
{
    const std::string raw = ReadEnvironmentVariable(name);
    if (raw.empty())
    {
        return;
    }

    std::chrono::milliseconds parsed{};
    if (TryParseMilliseconds(raw, parsed))
    {
        target = parsed;
    }
}

void ApplyBoolOverride(const char* name, bool& target)
{
    const std::string raw = ReadEnvironmentVariable(name);
    if (raw.empty())
    {
        return;
    }

    bool parsed = false;
    if (TryParseBool(raw, parsed))
    {
        target = parsed;
    }
}
} // namespace

AppConfig LoadAppConfigFromEnvironment()
{
    AppConfig config;

    ApplyMillisecondsOverride("EDR_LITE_DOWNLOAD_POLL_MS", config.downloadPollInterval);
    ApplyMillisecondsOverride("EDR_LITE_DOWNLOAD_QUIET_MS", config.downloadQuietPeriod);
    ApplyBoolOverride("EDR_LITE_CONSOLE_LOG", config.consoleLoggingEnabled);
    ApplyBoolOverride("EDR_LITE_FILE_LOG", config.fileLoggingEnabled);

    const std::string logFilePath = ReadEnvironmentVariable("EDR_LITE_LOG_FILE");
    if (!logFilePath.empty())
    {
        config.logFilePath = logFilePath;
    }

    return config;
}
