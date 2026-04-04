#include "MacosEventCollector.h"

#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string_view>
#include <thread>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
constexpr auto kDownloadsScanInterval = std::chrono::milliseconds(750);

std::unordered_set<int> SnapshotPids()
{
    const int maxPidCount = proc_listallpids(nullptr, 0);
    if (maxPidCount <= 0)
    {
        return {};
    }

    std::vector<pid_t> pids(static_cast<std::size_t>(maxPidCount));
    const int bytesWritten = proc_listallpids(
        pids.data(),
        static_cast<int>(pids.size() * sizeof(pid_t)));

    if (bytesWritten <= 0)
    {
        return {};
    }

    const int pidCount = bytesWritten / static_cast<int>(sizeof(pid_t));
    std::unordered_set<int> result;
    result.reserve(static_cast<std::size_t>(pidCount));

    for (int i = 0; i < pidCount; ++i)
    {
        if (pids[static_cast<std::size_t>(i)] > 0)
        {
            result.insert(static_cast<int>(pids[static_cast<std::size_t>(i)]));
        }
    }

    return result;
}

std::wstring Utf8ToWide(const char* text)
{
    if (!text || text[0] == '\0')
    {
        return {};
    }

    return std::filesystem::path(text).wstring();
}

std::wstring BytesToWide(const std::string& text)
{
    return std::wstring(text.begin(), text.end());
}

std::wstring QuoteArgumentIfNeeded(const std::wstring& arg)
{
    if (arg.find_first_of(L" \t\"") == std::wstring::npos)
    {
        return arg;
    }

    std::wstring quoted;
    quoted.reserve(arg.size() + 2);
    quoted.push_back(L'"');

    for (wchar_t ch : arg)
    {
        if (ch == L'"')
        {
            quoted.push_back(L'\\');
        }

        quoted.push_back(ch);
    }

    quoted.push_back(L'"');
    return quoted;
}

bool ReadCommandLine(int pid, std::wstring& commandLine)
{
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t size = 0;

    if (sysctl(mib, 3, nullptr, &size, nullptr, 0) != 0 || size <= sizeof(int))
    {
        return false;
    }

    std::vector<char> buffer(size);
    if (sysctl(mib, 3, buffer.data(), &size, nullptr, 0) != 0 || size <= sizeof(int))
    {
        return false;
    }

    const char* data = buffer.data();
    const char* end = buffer.data() + size;
    int argc = 0;
    std::memcpy(&argc, data, sizeof(argc));

    if (argc <= 0)
    {
        commandLine.clear();
        return true;
    }

    const char* cursor = data + sizeof(argc);

    while (cursor < end && *cursor != '\0')
    {
        ++cursor;
    }

    while (cursor < end && *cursor == '\0')
    {
        ++cursor;
    }

    std::vector<std::wstring> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));

    while (cursor < end && static_cast<int>(arguments.size()) < argc)
    {
        const char* argStart = cursor;

        while (cursor < end && *cursor != '\0')
        {
            ++cursor;
        }

        if (cursor > argStart)
        {
            arguments.push_back(BytesToWide(std::string(argStart, cursor)));
        }
        else
        {
            arguments.emplace_back();
        }

        while (cursor < end && *cursor == '\0')
        {
            ++cursor;
        }
    }

    std::wostringstream stream;
    for (std::size_t i = 0; i < arguments.size(); ++i)
    {
        if (i != 0)
        {
            stream << L' ';
        }

        stream << QuoteArgumentIfNeeded(arguments[i]);
    }

    commandLine = stream.str();
    return true;
}

bool BuildProcessStartEvent(int pid, ProcessStartEvent& event)
{
    if (pid <= 0)
    {
        return false;
    }

    struct proc_bsdinfo bsdInfo
    {
    };

    const int infoSize = proc_pidinfo(
        pid,
        PROC_PIDTBSDINFO,
        0,
        &bsdInfo,
        PROC_PIDTBSDINFO_SIZE);

    if (infoSize != PROC_PIDTBSDINFO_SIZE)
    {
        return false;
    }

    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {};
    const int pathLength = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));

    if (pathLength <= 0)
    {
        return false;
    }

    event.timestampQpc = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    event.pid = static_cast<uint32_t>(pid);
    event.ppid = static_cast<uint32_t>(bsdInfo.pbi_ppid);
    event.imagePath = Utf8ToWide(pathBuffer);
    if (!ReadCommandLine(pid, event.commandLine))
    {
        event.commandLine.clear();
    }

    return true;
}

std::filesystem::path ResolveDownloadsPath()
{
    const char* home = std::getenv("HOME");
    if (!home || home[0] == '\0')
    {
        return {};
    }

    return std::filesystem::path(home) / "Downloads";
}

std::wstring NormalizePath(const std::filesystem::path& path)
{
    std::filesystem::path normalized = path.lexically_normal();
    normalized.make_preferred();
    return normalized.wstring();
}

bool ShouldIgnoreDownloadPath(const std::filesystem::path& path)
{
    const std::wstring filename = path.filename().wstring();
    constexpr std::wstring_view kIgnoredSuffix = L".DS_Store";
    return filename.size() >= kIgnoredSuffix.size()
        && filename.compare(
            filename.size() - kIgnoredSuffix.size(),
            kIgnoredSuffix.size(),
            kIgnoredSuffix.data(),
            kIgnoredSuffix.size()) == 0;
}

MacosDownloadSnapshot BuildDownloadSnapshot(const std::filesystem::path& downloadsPath)
{
    MacosDownloadSnapshot snapshot;

    if (downloadsPath.empty())
    {
        return snapshot;
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(downloadsPath, ec);
    if (ec || !exists)
    {
        return snapshot;
    }

    std::filesystem::recursive_directory_iterator it(
        downloadsPath,
        std::filesystem::directory_options::skip_permission_denied,
        ec);

    if (ec)
    {
        return snapshot;
    }

    while (it != std::filesystem::recursive_directory_iterator())
    {
        const auto entry = *it;

        if (ShouldIgnoreDownloadPath(entry.path()))
        {
            it.increment(ec);
            if (ec)
            {
                ec.clear();
            }

            continue;
        }

        const auto status = entry.symlink_status(ec);
        if (ec || !std::filesystem::is_regular_file(status))
        {
            ec.clear();
            it.increment(ec);
            if (ec)
            {
                ec.clear();
            }

            continue;
        }

        const auto size = entry.file_size(ec);
        if (ec)
        {
            ec.clear();
            it.increment(ec);
            if (ec)
            {
                ec.clear();
            }

            continue;
        }

        const auto writeTime = entry.last_write_time(ec);
        if (ec)
        {
            ec.clear();
            it.increment(ec);
            if (ec)
            {
                ec.clear();
            }

            continue;
        }

        MacosDownloadFileState state{};
        state.size = size;
        state.writeTime = writeTime;
        snapshot.emplace(NormalizePath(entry.path()), std::move(state));

        it.increment(ec);
        if (ec)
        {
            ec.clear();
        }
    }

    return snapshot;
}
} // namespace

bool MacosEventCollector::Start(OnProcessStart cb)
{
    if (m_running.load())
    {
        return false;
    }

    m_onProcessStart = std::move(cb);
    m_knownPids = SnapshotPids();
    m_downloadsPath = ResolveDownloadsPath();
    m_downloadSnapshot = BuildDownloadSnapshot(m_downloadsPath);
    std::cout << "MacOS detected, downloads path: " << m_downloadsPath << std::endl;

    m_running.store(true);

    try
    {
        m_worker = std::thread(&MacosEventCollector::Run, this);
    }
    catch (...)
    {
        m_running.store(false);
        m_knownPids.clear();
        return false;
    }

    return true;
}

void MacosEventCollector::SetOnDownloadActivity(OnDownloadActivity cb)
{
    m_onDownloadActivity = std::move(cb);
}

void MacosEventCollector::Stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    if (m_worker.joinable())
    {
        m_worker.join();
    }

    m_knownPids.clear();
    m_downloadSnapshot.clear();
    m_downloadsPath.clear();
}

void MacosEventCollector::Run()
{
    auto lastDownloadsScan = std::chrono::steady_clock::now();

    while (m_running.load())
    {
        std::unordered_set<int> currentPids = SnapshotPids();

        for (int pid : currentPids)
        {
            if (!m_running.load())
            {
                break;
            }

            if (m_knownPids.find(pid) != m_knownPids.end())
            {
                continue;
            }

            ProcessStartEvent event{};
            if (!BuildProcessStartEvent(pid, event))
            {
                continue;
            }

            if (m_onProcessStart)
            {
                m_onProcessStart(event);
            }
        }

        if (m_onDownloadActivity)
        {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastDownloadsScan >= kDownloadsScanInterval)
            {
                PollDownloads();
                lastDownloadsScan = now;
            }
        }

        m_knownPids = std::move(currentPids);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    m_running.store(false);
}

void MacosEventCollector::PollDownloads()
{
    if (!m_onDownloadActivity || m_downloadsPath.empty())
    {
        return;
    }

    MacosDownloadSnapshot currentSnapshot = BuildDownloadSnapshot(m_downloadsPath);
    const uint64_t nowQpc = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());

    std::cout << "Polling downloads: previous snapshot size " << m_downloadSnapshot.size()
              << ", current snapshot size " << currentSnapshot.size() << std::endl;

    for (const auto& [path, state] : currentSnapshot)
    {
        const auto previous = m_downloadSnapshot.find(path);
        const bool changed = previous == m_downloadSnapshot.end()
            || previous->second.size != state.size
            || previous->second.writeTime != state.writeTime;

        if (!changed)
        {
            continue;
        }

        std::cout << "Download change detected for: " << std::string(path.begin(), path.end()) << std::endl;

        DownloadFileEvent event{};
        event.timestampQpc = nowQpc;
        event.path = path;
        m_onDownloadActivity(event);
    }

    m_downloadSnapshot = std::move(currentSnapshot);
}
