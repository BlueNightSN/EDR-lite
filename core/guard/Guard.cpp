#include "Guard.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <curl/curl.h>
#endif

namespace
{
using Clock = std::chrono::system_clock;

constexpr uintmax_t kMaxAutoUploadBytes = 32ULL * 1024ULL * 1024ULL;
constexpr auto kCacheTtl = std::chrono::hours(24);
constexpr auto kInitialAnalysisPollDelay = std::chrono::seconds(20);
constexpr auto kAnalysisPollInterval = std::chrono::seconds(20);
constexpr auto kAnalysisPollTimeout = std::chrono::minutes(3);
constexpr long kCurlConnectTimeoutSeconds = 5;
constexpr long kCurlRequestTimeoutSeconds = 30;

std::mutex g_logMutex;

std::wstring BytesToWide(const std::string& text)
{
    return std::wstring(text.begin(), text.end());
}

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

void LogLine(const std::wstring& line)
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::wcout << line << L"\n";
}

void LogDownloadLine(const std::wstring& line)
{
    LogLine(L"[download-scan] " + line);
}

enum class DownloadVerdict
{
    Clean,
    Malicious,
    Unknown,
    Error
};

const wchar_t* VerdictToWideString(const DownloadVerdict verdict)
{
    switch (verdict)
    {
    case DownloadVerdict::Clean:
        return L"Clean";
    case DownloadVerdict::Malicious:
        return L"Malicious";
    case DownloadVerdict::Unknown:
        return L"Unknown";
    case DownloadVerdict::Error:
        return L"Error";
    }

    return L"Unknown";
}

const char* VerdictToStorageString(const DownloadVerdict verdict)
{
    switch (verdict)
    {
    case DownloadVerdict::Clean:
        return "clean";
    case DownloadVerdict::Malicious:
        return "malicious";
    case DownloadVerdict::Unknown:
        return "unknown";
    case DownloadVerdict::Error:
        return "error";
    }

    return "unknown";
}

std::optional<DownloadVerdict> VerdictFromStorageString(const std::string& value)
{
    if (value == "clean")
    {
        return DownloadVerdict::Clean;
    }

    if (value == "malicious")
    {
        return DownloadVerdict::Malicious;
    }

    if (value == "unknown")
    {
        return DownloadVerdict::Unknown;
    }

    if (value == "error")
    {
        return DownloadVerdict::Error;
    }

    return std::nullopt;
}

struct VerdictRecord
{
    DownloadVerdict verdict = DownloadVerdict::Unknown;
    std::time_t recordedAt = 0;
    int maliciousCount = 0;
    int suspiciousCount = 0;
};

struct ScanOutcome
{
    DownloadVerdict verdict = DownloadVerdict::Unknown;
    int maliciousCount = 0;
    int suspiciousCount = 0;
    bool cacheable = false;
    std::wstring detail;
};

struct AnalysisStats
{
    int malicious = 0;
    int suspicious = 0;
};

struct HttpResponse
{
    long statusCode = 0;
    std::string body;
    std::string error;
    bool canceled = false;
};

std::filesystem::path ResolveCacheFilePath()
{
#if defined(_WIN32)
    const char* localAppData = std::getenv("LOCALAPPDATA");
    std::filesystem::path base = (localAppData && localAppData[0] != '\0')
        ? std::filesystem::path(localAppData)
        : std::filesystem::temp_directory_path();
    return base / "EDR-lite" / "virustotal_cache.tsv";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    std::filesystem::path base = (home && home[0] != '\0')
        ? std::filesystem::path(home) / "Library" / "Application Support"
        : std::filesystem::temp_directory_path();
    return base / "EDR-lite" / "virustotal_cache.tsv";
#else
    return std::filesystem::temp_directory_path() / "EDR-lite" / "virustotal_cache.tsv";
#endif
}

void EnsureCacheDirectoryExists(const std::filesystem::path& cachePath)
{
    std::error_code ec;
    const auto parent = cachePath.parent_path();
    if (!parent.empty())
    {
        std::filesystem::create_directories(parent, ec);
    }
}

std::wstring FormatFinalVerdictMessage(
    const std::wstring& path,
    const std::string& sha256,
    const ScanOutcome& outcome)
{
    std::wostringstream stream;
    stream << L"Final verdict for " << path
           << L" SHA256=" << BytesToWide(sha256)
           << L" Verdict=" << VerdictToWideString(outcome.verdict);

    if (outcome.maliciousCount > 0 || outcome.suspiciousCount > 0)
    {
        stream << L" (malicious=" << outcome.maliciousCount
               << L", suspicious=" << outcome.suspiciousCount << L")";
    }

    if (!outcome.detail.empty())
    {
        stream << L" " << outcome.detail;
    }

    return stream.str();
}

std::string TrimAsciiWhitespaceCopy(const std::string& value)
{
    std::size_t start = 0;
    while (start < value.size()
        && std::isspace(static_cast<unsigned char>(value[start])))
    {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start
        && std::isspace(static_cast<unsigned char>(value[end - 1])))
    {
        --end;
    }

    return value.substr(start, end - start);
}

std::string StripOptionalQuotes(const std::string& value)
{
    if (value.size() >= 2)
    {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
        {
            return value.substr(1, value.size() - 2);
        }
    }

    return value;
}

std::string ReadApiKeyFromDotEnv(const std::filesystem::path& envPath)
{
    std::ifstream input(envPath);
    if (!input)
    {
        return {};
    }

    std::string line;
    while (std::getline(input, line))
    {
        std::string trimmed = TrimAsciiWhitespaceCopy(line);
        if (trimmed.empty() || trimmed[0] == '#')
        {
            continue;
        }

        const std::size_t equals = trimmed.find('=');
        if (equals == std::string::npos)
        {
            continue;
        }

        const std::string key = TrimAsciiWhitespaceCopy(trimmed.substr(0, equals));
        if (key != "VT_API_KEY")
        {
            continue;
        }

        std::string value = TrimAsciiWhitespaceCopy(trimmed.substr(equals + 1));
        value = StripOptionalQuotes(value);
        return value;
    }

    return {};
}

std::string LoadVirusTotalApiKey()
{
    const char* envKey = std::getenv("VT_API_KEY");
    if (envKey && envKey[0] != '\0')
    {
        return envKey;
    }

    const std::string fileKey = ReadApiKeyFromDotEnv(".env");
    if (!fileKey.empty())
    {
        return fileKey;
    }

    return {};
}

std::vector<std::string> SplitTabs(const std::string& line)
{
    std::vector<std::string> parts;
    std::size_t start = 0;

    while (start <= line.size())
    {
        const std::size_t tab = line.find('\t', start);
        if (tab == std::string::npos)
        {
            parts.push_back(line.substr(start));
            break;
        }

        parts.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }

    return parts;
}

std::optional<std::time_t> ParseTimeValue(const std::string& text)
{
    try
    {
        const long long value = std::stoll(text);
        if (value < std::numeric_limits<std::time_t>::min()
            || value > std::numeric_limits<std::time_t>::max())
        {
            return std::nullopt;
        }

        return static_cast<std::time_t>(value);
    }
    catch (...)
    {
        return std::nullopt;
    }
}

std::optional<int> ParseIntValue(const std::string& text)
{
    try
    {
        return std::stoi(text);
    }
    catch (...)
    {
        return std::nullopt;
    }
}

std::unordered_map<std::string, VerdictRecord> LoadCache(const std::filesystem::path& cachePath)
{
    std::unordered_map<std::string, VerdictRecord> cache;

    std::ifstream input(cachePath);
    if (!input)
    {
        return cache;
    }

    std::string line;
    while (std::getline(input, line))
    {
        const auto parts = SplitTabs(line);
        if (parts.size() < 5)
        {
            continue;
        }

        const auto verdict = VerdictFromStorageString(parts[2]);
        const auto recordedAt = ParseTimeValue(parts[1]);
        const auto malicious = ParseIntValue(parts[3]);
        const auto suspicious = ParseIntValue(parts[4]);

        if (!verdict || !recordedAt || !malicious || !suspicious)
        {
            continue;
        }

        cache.emplace(
            parts[0],
            VerdictRecord{
                *verdict,
                *recordedAt,
                *malicious,
                *suspicious
            });
    }

    return cache;
}

void SaveCache(
    const std::filesystem::path& cachePath,
    const std::unordered_map<std::string, VerdictRecord>& cache)
{
    EnsureCacheDirectoryExists(cachePath);

    std::ofstream output(cachePath, std::ios::trunc);
    if (!output)
    {
        return;
    }

    for (const auto& [sha256, record] : cache)
    {
        output << sha256 << '\t'
               << static_cast<long long>(record.recordedAt) << '\t'
               << VerdictToStorageString(record.verdict) << '\t'
               << record.maliciousCount << '\t'
               << record.suspiciousCount << '\n';
    }
}

bool IsRecordFresh(const VerdictRecord& record)
{
    const auto now = Clock::now();
    const auto recordedAt = Clock::from_time_t(record.recordedAt);
    return now - recordedAt <= kCacheTtl;
}

std::optional<VerdictRecord> GetFreshCachedVerdict(
    const std::unordered_map<std::string, VerdictRecord>& cache,
    const std::string& sha256)
{
    const auto it = cache.find(sha256);
    if (it == cache.end() || !IsRecordFresh(it->second))
    {
        return std::nullopt;
    }

    return it->second;
}

std::wstring BuildCacheDetail(const VerdictRecord& record)
{
    std::wostringstream stream;
    stream << L"(cached, malicious=" << record.maliciousCount
           << L", suspicious=" << record.suspiciousCount << L")";
    return stream.str();
}

struct Sha256Context
{
    uint64_t bitCount = 0;
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    unsigned char buffer[64] = {};
    std::size_t bufferLength = 0;
};

uint32_t RotateRight(const uint32_t value, const uint32_t count)
{
    return (value >> count) | (value << (32u - count));
}

void TransformSha256Block(Sha256Context& context, const unsigned char block[64])
{
    static constexpr uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    uint32_t schedule[64] = {};
    for (int i = 0; i < 16; ++i)
    {
        const int offset = i * 4;
        schedule[i] = (static_cast<uint32_t>(block[offset]) << 24u)
            | (static_cast<uint32_t>(block[offset + 1]) << 16u)
            | (static_cast<uint32_t>(block[offset + 2]) << 8u)
            | static_cast<uint32_t>(block[offset + 3]);
    }

    for (int i = 16; i < 64; ++i)
    {
        const uint32_t s0 = RotateRight(schedule[i - 15], 7u)
            ^ RotateRight(schedule[i - 15], 18u)
            ^ (schedule[i - 15] >> 3u);
        const uint32_t s1 = RotateRight(schedule[i - 2], 17u)
            ^ RotateRight(schedule[i - 2], 19u)
            ^ (schedule[i - 2] >> 10u);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    uint32_t a = context.state[0];
    uint32_t b = context.state[1];
    uint32_t c = context.state[2];
    uint32_t d = context.state[3];
    uint32_t e = context.state[4];
    uint32_t f = context.state[5];
    uint32_t g = context.state[6];
    uint32_t h = context.state[7];

    for (int i = 0; i < 64; ++i)
    {
        const uint32_t s1 = RotateRight(e, 6u) ^ RotateRight(e, 11u) ^ RotateRight(e, 25u);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + s1 + ch + k[i] + schedule[i];
        const uint32_t s0 = RotateRight(a, 2u) ^ RotateRight(a, 13u) ^ RotateRight(a, 22u);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    context.state[0] += a;
    context.state[1] += b;
    context.state[2] += c;
    context.state[3] += d;
    context.state[4] += e;
    context.state[5] += f;
    context.state[6] += g;
    context.state[7] += h;
}

void UpdateSha256(Sha256Context& context, const unsigned char* data, std::size_t length)
{
    while (length > 0)
    {
        const std::size_t chunk = std::min(length, 64u - context.bufferLength);
        std::memcpy(context.buffer + context.bufferLength, data, chunk);
        context.bufferLength += chunk;
        context.bitCount += static_cast<uint64_t>(chunk) * 8u;
        data += chunk;
        length -= chunk;

        if (context.bufferLength == 64)
        {
            TransformSha256Block(context, context.buffer);
            context.bufferLength = 0;
        }
    }
}

std::string FinalizeSha256(Sha256Context& context)
{
    context.buffer[context.bufferLength++] = 0x80u;

    if (context.bufferLength > 56)
    {
        while (context.bufferLength < 64)
        {
            context.buffer[context.bufferLength++] = 0;
        }

        TransformSha256Block(context, context.buffer);
        context.bufferLength = 0;
    }

    while (context.bufferLength < 56)
    {
        context.buffer[context.bufferLength++] = 0;
    }

    for (int i = 7; i >= 0; --i)
    {
        context.buffer[context.bufferLength++] = static_cast<unsigned char>((context.bitCount >> (i * 8)) & 0xffu);
    }

    TransformSha256Block(context, context.buffer);

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const uint32_t value : context.state)
    {
        stream << std::setw(8) << value;
    }

    return stream.str();
}

bool ComputeSha256File(const std::filesystem::path& path, std::string& sha256)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        return false;
    }

    Sha256Context context;
    std::vector<unsigned char> buffer(64 * 1024);

    while (input)
    {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
        {
            UpdateSha256(context, buffer.data(), static_cast<std::size_t>(bytesRead));
        }
    }

    if (!input.eof() && input.fail())
    {
        return false;
    }

    sha256 = FinalizeSha256(context);
    return true;
}

std::size_t FindJsonKey(
    const std::string_view json,
    const std::string_view key,
    const std::size_t start = 0)
{
    std::string token;
    token.reserve(key.size() + 2);
    token.push_back('"');
    token.append(key.begin(), key.end());
    token.push_back('"');
    return json.find(token, start);
}

bool FindMatchingObjectRange(
    const std::string_view json,
    const std::size_t objectStart,
    std::size_t& objectEnd)
{
    if (objectStart >= json.size() || json[objectStart] != '{')
    {
        return false;
    }

    int depth = 0;
    bool inString = false;
    bool escape = false;

    for (std::size_t i = objectStart; i < json.size(); ++i)
    {
        const char ch = json[i];
        if (inString)
        {
            if (escape)
            {
                escape = false;
            }
            else if (ch == '\\')
            {
                escape = true;
            }
            else if (ch == '"')
            {
                inString = false;
            }

            continue;
        }

        if (ch == '"')
        {
            inString = true;
            continue;
        }

        if (ch == '{')
        {
            ++depth;
        }
        else if (ch == '}')
        {
            --depth;
            if (depth == 0)
            {
                objectEnd = i;
                return true;
            }
        }
    }

    return false;
}

bool ExtractJsonObject(
    const std::string_view json,
    const std::string_view key,
    std::string_view& objectView)
{
    const std::size_t keyPos = FindJsonKey(json, key);
    if (keyPos == std::string_view::npos)
    {
        return false;
    }

    const std::size_t colonPos = json.find(':', keyPos + key.size() + 2);
    if (colonPos == std::string_view::npos)
    {
        return false;
    }

    const std::size_t objectStart = json.find('{', colonPos + 1);
    if (objectStart == std::string_view::npos)
    {
        return false;
    }

    std::size_t objectEnd = std::string_view::npos;
    if (!FindMatchingObjectRange(json, objectStart, objectEnd))
    {
        return false;
    }

    objectView = json.substr(objectStart, objectEnd - objectStart + 1);
    return true;
}

bool ExtractJsonString(
    const std::string_view json,
    const std::string_view key,
    std::string& value)
{
    const std::size_t keyPos = FindJsonKey(json, key);
    if (keyPos == std::string_view::npos)
    {
        return false;
    }

    const std::size_t colonPos = json.find(':', keyPos + key.size() + 2);
    if (colonPos == std::string_view::npos)
    {
        return false;
    }

    std::size_t quotePos = json.find('"', colonPos + 1);
    if (quotePos == std::string_view::npos)
    {
        return false;
    }

    ++quotePos;
    std::string result;
    bool escape = false;
    for (std::size_t i = quotePos; i < json.size(); ++i)
    {
        const char ch = json[i];
        if (escape)
        {
            result.push_back(ch);
            escape = false;
            continue;
        }

        if (ch == '\\')
        {
            escape = true;
            continue;
        }

        if (ch == '"')
        {
            value = std::move(result);
            return true;
        }

        result.push_back(ch);
    }

    return false;
}

bool ExtractJsonInt(
    const std::string_view json,
    const std::string_view key,
    int& value)
{
    const std::size_t keyPos = FindJsonKey(json, key);
    if (keyPos == std::string_view::npos)
    {
        return false;
    }

    const std::size_t colonPos = json.find(':', keyPos + key.size() + 2);
    if (colonPos == std::string_view::npos)
    {
        return false;
    }

    std::size_t valueStart = colonPos + 1;
    while (valueStart < json.size()
        && std::isspace(static_cast<unsigned char>(json[valueStart])))
    {
        ++valueStart;
    }

    std::size_t valueEnd = valueStart;
    if (valueEnd < json.size() && (json[valueEnd] == '-' || json[valueEnd] == '+'))
    {
        ++valueEnd;
    }

    while (valueEnd < json.size()
        && std::isdigit(static_cast<unsigned char>(json[valueEnd])))
    {
        ++valueEnd;
    }

    if (valueEnd == valueStart)
    {
        return false;
    }

    try
    {
        value = std::stoi(std::string(json.substr(valueStart, valueEnd - valueStart)));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

std::optional<AnalysisStats> ParseFileLookupStats(const std::string& body)
{
    std::string_view statsObject;
    if (!ExtractJsonObject(body, "last_analysis_stats", statsObject))
    {
        return std::nullopt;
    }

    AnalysisStats stats;
    if (!ExtractJsonInt(statsObject, "malicious", stats.malicious))
    {
        return std::nullopt;
    }

    ExtractJsonInt(statsObject, "suspicious", stats.suspicious);
    return stats;
}

std::optional<std::string> ParseUploadAnalysisId(const std::string& body)
{
    std::string_view dataObject;
    if (!ExtractJsonObject(body, "data", dataObject))
    {
        return std::nullopt;
    }

    std::string id;
    if (!ExtractJsonString(dataObject, "id", id))
    {
        return std::nullopt;
    }

    return id;
}

struct AnalysisStatus
{
    std::string status;
    AnalysisStats stats;
};

std::optional<AnalysisStatus> ParseAnalysisStatus(const std::string& body)
{
    std::string_view attributesObject;
    if (!ExtractJsonObject(body, "attributes", attributesObject))
    {
        return std::nullopt;
    }

    AnalysisStatus result;
    if (!ExtractJsonString(attributesObject, "status", result.status))
    {
        return std::nullopt;
    }

    std::string_view statsObject;
    if (ExtractJsonObject(attributesObject, "stats", statsObject))
    {
        ExtractJsonInt(statsObject, "malicious", result.stats.malicious);
        ExtractJsonInt(statsObject, "suspicious", result.stats.suspicious);
    }

    return result;
}

std::wstring BuildStatsDetail(const AnalysisStats& stats, const std::wstring& prefix)
{
    std::wostringstream stream;
    if (!prefix.empty())
    {
        stream << prefix << L' ';
    }

    stream << L"(malicious=" << stats.malicious
           << L", suspicious=" << stats.suspicious << L")";
    return stream.str();
}

std::wstring BuildAnalysisProgressDetail(const AnalysisStatus& status)
{
    std::wostringstream stream;
    stream << L"VirusTotal analysis status="
           << BytesToWide(status.status)
           << L" (malicious=" << status.stats.malicious
           << L", suspicious=" << status.stats.suspicious << L")";
    return stream.str();
}

ScanOutcome OutcomeFromStats(const AnalysisStats& stats, const std::wstring& detailPrefix)
{
    ScanOutcome outcome;
    outcome.verdict = stats.malicious > 0 ? DownloadVerdict::Malicious : DownloadVerdict::Clean;
    outcome.maliciousCount = stats.malicious;
    outcome.suspiciousCount = stats.suspicious;
    outcome.cacheable = true;
    outcome.detail = BuildStatsDetail(stats, detailPrefix);
    return outcome;
}

constexpr const char* kUserAgent = "EDR-lite/1.0";

#if defined(__APPLE__)

void EnsureCurlGlobalInit()
{
    static std::once_flag once;
    std::call_once(once, []()
        {
            curl_global_init(CURL_GLOBAL_DEFAULT);
        });
}

std::size_t CurlWriteCallback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata)
{
    if (!userdata)
    {
        return 0;
    }

    std::string* output = static_cast<std::string*>(userdata);
    output->append(ptr, size * nmemb);
    return size * nmemb;
}

int CurlProgressCallback(
    void* clientp,
    curl_off_t,
    curl_off_t,
    curl_off_t,
    curl_off_t)
{
    if (!clientp)
    {
        return 0;
    }

    const std::atomic<bool>* stopRequested = static_cast<const std::atomic<bool>*>(clientp);
    return stopRequested->load() ? 1 : 0;
}

void ConfigureCurlCommon(
    CURL* curl,
    HttpResponse& response,
    const std::atomic<bool>& stopRequested)
{
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, kCurlConnectTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, kCurlRequestTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kUserAgent);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, &CurlProgressCallback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stopRequested);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
}

HttpResponse PerformGetRequest(
    const std::string& url,
    const std::string& apiKey,
    const std::atomic<bool>& stopRequested)
{
    HttpResponse response;
    EnsureCurlGlobalInit();

    CURL* curl = curl_easy_init();
    if (!curl)
    {
        response.error = "Failed to initialize curl";
        return response;
    }

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());
    headers = curl_slist_append(headers, "accept: application/json");

    ConfigureCurlCommon(curl, response, stopRequested);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    const CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_ABORTED_BY_CALLBACK)
    {
        response.canceled = true;
        response.error = "Canceled";
    }
    else if (code != CURLE_OK)
    {
        response.error = curl_easy_strerror(code);
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

HttpResponse PerformFileUploadRequest(
    const std::string& url,
    const std::string& apiKey,
    const std::filesystem::path& path,
    const std::atomic<bool>& stopRequested)
{
    HttpResponse response;
    EnsureCurlGlobalInit();

    CURL* curl = curl_easy_init();
    if (!curl)
    {
        response.error = "Failed to initialize curl";
        return response;
    }

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());
    headers = curl_slist_append(headers, "accept: application/json");

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    const std::string narrowPath = path.string();
    curl_mime_filedata(part, narrowPath.c_str());

    ConfigureCurlCommon(curl, response, stopRequested);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    const CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_ABORTED_BY_CALLBACK)
    {
        response.canceled = true;
        response.error = "Canceled";
    }
    else if (code != CURLE_OK)
    {
        response.error = curl_easy_strerror(code);
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

#else

HttpResponse PerformGetRequest(
    const std::string&,
    const std::string&,
    const std::atomic<bool>&)
{
    HttpResponse response;
    response.error = "VirusTotal HTTP client is unavailable on this platform build";
    return response;
}

HttpResponse PerformFileUploadRequest(
    const std::string&,
    const std::string&,
    const std::filesystem::path&,
    const std::atomic<bool>&)
{
    HttpResponse response;
    response.error = "VirusTotal HTTP client is unavailable on this platform build";
    return response;
}

#endif

} // namespace

struct Guard::DownloadScanState
{
    std::atomic<bool> stopRequested{ false };
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::queue<std::wstring> pathQueue;
    std::unordered_set<std::wstring> queuedOrActivePaths;
    std::unordered_set<std::string> activeHashes;

    std::mutex cacheMutex;
    std::unordered_map<std::string, VerdictRecord> cache;
    std::filesystem::path cachePath;

    std::thread worker;
    std::string apiKey;
    bool missingKeyLogged = false;
    bool workerRunning = false;

    DownloadScanState()
        : cachePath(ResolveCacheFilePath())
        , cache(LoadCache(cachePath))
    {
        apiKey = LoadVirusTotalApiKey();

        try
        {
            worker = std::thread(&DownloadScanState::Run, this);
            workerRunning = true;
        }
        catch (const std::exception&)
        {
            workerRunning = false;
            LogDownloadLine(L"Failed to start background download scanner thread.");
        }
        catch (...)
        {
            workerRunning = false;
            LogDownloadLine(L"Failed to start background download scanner thread.");
        }
    }

    ~DownloadScanState()
    {
        stopRequested.store(true);
        queueCv.notify_all();

        if (worker.joinable())
        {
            worker.join();
        }
    }

    void Enqueue(const std::wstring& rawPath)
    {
        if (!workerRunning)
        {
            LogDownloadLine(L"Skipping enqueue because the download scanner worker is not running.");
            return;
        }

        const std::wstring normalized = NormalizePathKey(rawPath);
        if (normalized.empty())
        {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (stopRequested.load())
            {
                return;
            }

            if (!queuedOrActivePaths.insert(normalized).second)
            {
                return;
            }

            pathQueue.push(normalized);
        }

        LogDownloadLine(L"Queued file for VirusTotal scan: " + normalized);
        queueCv.notify_one();
    }

    void Run()
    {
        while (true)
        {
            std::wstring path;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCv.wait(lock, [&]()
                    {
                        return stopRequested.load() || !pathQueue.empty();
                    });

                if (stopRequested.load())
                {
                    while (!pathQueue.empty())
                    {
                        queuedOrActivePaths.erase(pathQueue.front());
                        pathQueue.pop();
                    }

                    return;
                }

                path = std::move(pathQueue.front());
                pathQueue.pop();
            }

            ProcessPath(path);

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                queuedOrActivePaths.erase(path);
            }
        }
    }

    void ProcessPath(const std::wstring& path)
    {
        const std::filesystem::path fsPath(path);
        std::error_code ec;

        if (!std::filesystem::exists(fsPath, ec) || ec)
        {
            LogDownloadLine(L"File disappeared before scan: " + path);
            return;
        }

        const auto status = std::filesystem::status(fsPath, ec);
        if (ec || !std::filesystem::is_regular_file(status))
        {
            LogDownloadLine(L"Skipping non-regular file: " + path);
            return;
        }

        std::string sha256;
        if (!ComputeSha256File(fsPath, sha256))
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Error;
            outcome.detail = L"(failed to hash file)";
            LogDownloadLine(FormatFinalVerdictMessage(path, "<hash-error>", outcome));
            return;
        }

        LogDownloadLine(L"Computed SHA256 for " + path + L": " + BytesToWide(sha256));

        {
            std::lock_guard<std::mutex> cacheLock(cacheMutex);
            if (const auto cached = GetFreshCachedVerdict(cache, sha256))
            {
                ScanOutcome outcome;
                outcome.verdict = cached->verdict;
                outcome.maliciousCount = cached->maliciousCount;
                outcome.suspiciousCount = cached->suspiciousCount;
                outcome.cacheable = true;
                outcome.detail = BuildCacheDetail(*cached);
                LogDownloadLine(FormatFinalVerdictMessage(path, sha256, outcome));
                return;
            }
        }

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (!activeHashes.insert(sha256).second)
            {
                LogDownloadLine(L"Skipping duplicate in-flight hash for " + path);
                return;
            }
        }

        const auto releaseHash = [this, &sha256]()
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            activeHashes.erase(sha256);
        };

        ScanOutcome outcome = ScanWithVirusTotal(path, fsPath, sha256);
        releaseHash();

        if (outcome.cacheable)
        {
            const VerdictRecord record{
                outcome.verdict,
                Clock::to_time_t(Clock::now()),
                outcome.maliciousCount,
                outcome.suspiciousCount
            };

            std::lock_guard<std::mutex> cacheLock(cacheMutex);
            cache[sha256] = record;
            SaveCache(cachePath, cache);
        }

        LogDownloadLine(FormatFinalVerdictMessage(path, sha256, outcome));
    }

    ScanOutcome ScanWithVirusTotal(
        const std::wstring& path,
        const std::filesystem::path& fsPath,
        const std::string& sha256)
    {
        if (stopRequested.load())
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(scan canceled during shutdown)";
            return outcome;
        }

        if (apiKey.empty())
        {
            if (!missingKeyLogged)
            {
                LogDownloadLine(L"VT_API_KEY is not set. VirusTotal scanning is disabled.");
                missingKeyLogged = true;
            }

            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(VT_API_KEY missing)";
            return outcome;
        }

        LogDownloadLine(L"VirusTotal lookup by hash: " + BytesToWide(sha256));
        const HttpResponse lookupResponse = PerformGetRequest(
            "https://www.virustotal.com/api/v3/files/" + sha256,
            apiKey,
            stopRequested);

        if (lookupResponse.canceled)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(lookup canceled during shutdown)";
            return outcome;
        }

        if (lookupResponse.statusCode == 200)
        {
            if (const auto stats = ParseFileLookupStats(lookupResponse.body))
            {
                return OutcomeFromStats(*stats, L"(hash lookup)");
            }

            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Error;
            outcome.detail = L"(failed to parse lookup response)";
            return outcome;
        }

        if (lookupResponse.statusCode == 429)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(VirusTotal quota exceeded)";
            return outcome;
        }

        if (lookupResponse.statusCode != 404)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(lookup failed: HTTP "
                + BytesToWide(std::to_string(lookupResponse.statusCode))
                + L")";

            if (!lookupResponse.error.empty())
            {
                outcome.detail += L" " + BytesToWide(lookupResponse.error);
            }

            return outcome;
        }

        std::error_code sizeEc;
        const uintmax_t fileSize = std::filesystem::file_size(fsPath, sizeEc);
        if (sizeEc)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Error;
            outcome.detail = L"(failed to read file size before upload)";
            return outcome;
        }

        if (fileSize > kMaxAutoUploadBytes)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(hash unknown, upload skipped because file is over 32 MB)";
            return outcome;
        }

        LogDownloadLine(L"VirusTotal hash miss, uploading file: " + path);
        const HttpResponse uploadResponse = PerformFileUploadRequest(
            "https://www.virustotal.com/api/v3/files",
            apiKey,
            fsPath,
            stopRequested);

        if (uploadResponse.canceled)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(upload canceled during shutdown)";
            return outcome;
        }

        if (uploadResponse.statusCode == 429)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(upload skipped because VirusTotal quota was exceeded)";
            return outcome;
        }

        if (uploadResponse.statusCode < 200 || uploadResponse.statusCode >= 300)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Unknown;
            outcome.detail = L"(upload failed: HTTP "
                + BytesToWide(std::to_string(uploadResponse.statusCode))
                + L")";

            if (!uploadResponse.error.empty())
            {
                outcome.detail += L" " + BytesToWide(uploadResponse.error);
            }

            return outcome;
        }

        const auto analysisId = ParseUploadAnalysisId(uploadResponse.body);
        if (!analysisId)
        {
            ScanOutcome outcome;
            outcome.verdict = DownloadVerdict::Error;
            outcome.detail = L"(failed to parse upload response)";
            return outcome;
        }

        std::this_thread::sleep_for(kInitialAnalysisPollDelay);

        const auto deadline = std::chrono::steady_clock::now() + kAnalysisPollTimeout;
        while (!stopRequested.load() && std::chrono::steady_clock::now() < deadline)
        {
            LogDownloadLine(L"Polling VirusTotal analysis: " + BytesToWide(*analysisId));
            const HttpResponse analysisResponse = PerformGetRequest(
                "https://www.virustotal.com/api/v3/analyses/" + *analysisId,
                apiKey,
                stopRequested);

            if (analysisResponse.canceled)
            {
                ScanOutcome outcome;
                outcome.verdict = DownloadVerdict::Unknown;
                outcome.detail = L"(analysis polling canceled during shutdown)";
                return outcome;
            }

            if (analysisResponse.statusCode == 200)
            {
                const auto status = ParseAnalysisStatus(analysisResponse.body);
                if (!status)
                {
                    ScanOutcome outcome;
                    outcome.verdict = DownloadVerdict::Error;
                    outcome.detail = L"(failed to parse analysis response)";
                    return outcome;
                }

                LogDownloadLine(BuildAnalysisProgressDetail(*status));

                if (status->status == "completed")
                {
                    return OutcomeFromStats(status->stats, L"(uploaded file analysis)");
                }
            }
            else if (analysisResponse.statusCode == 429)
            {
                ScanOutcome outcome;
                outcome.verdict = DownloadVerdict::Unknown;
                outcome.detail = L"(analysis polling quota exceeded)";
                return outcome;
            }
            else if (analysisResponse.statusCode >= 400)
            {
                ScanOutcome outcome;
                outcome.verdict = DownloadVerdict::Unknown;
                outcome.detail = L"(analysis polling failed: HTTP "
                    + BytesToWide(std::to_string(analysisResponse.statusCode))
                    + L")";
                return outcome;
            }

            std::this_thread::sleep_for(kAnalysisPollInterval);
        }

        ScanOutcome outcome;
        outcome.verdict = DownloadVerdict::Unknown;
        outcome.detail = stopRequested.load()
            ? L"(analysis polling canceled during shutdown)"
            : L"(analysis polling timed out; VirusTotal may still be queued or in-progress)";
        return outcome;
    }
};

Guard::Guard()
    : m_downloadScan(std::make_unique<DownloadScanState>())
{
}

Guard::~Guard() = default;

void Guard::AddRule(std::unique_ptr<IRule> rule)
{
    if (!rule)
    {
        return;
    }

    m_rules.push_back(std::move(rule));
}

bool Guard::RemoveRuleByIndex(std::size_t index)
{
    if (index >= m_rules.size())
    {
        return false;
    }

    m_rules.erase(m_rules.begin() + static_cast<std::ptrdiff_t>(index));
    return true;
}

std::vector<Alert> Guard::Inspect(const ProcessStartEvent& e) const
{
    std::vector<Alert> alerts;

    for (const auto& rule : m_rules)
    {
        if (!rule)
        {
            continue;
        }

        Alert alert;
        if (rule->Evaluate(e, alert))
        {
            alerts.push_back(std::move(alert));
        }
    }

    return alerts;
}

void Guard::InspectDownloadPath(const std::wstring& path)
{
    if (path.empty() || !m_downloadScan)
    {
        return;
    }

    m_downloadScan->Enqueue(path);
}

std::size_t Guard::RuleCount() const
{
    return m_rules.size();
}
