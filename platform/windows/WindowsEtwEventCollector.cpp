#include "WindowsEtwEventCollector.h"

#include <KnownFolders.h>
#include <ShlObj.h>

#include <chrono>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <initializer_list>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include "EtwTdhHelpers.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

static const GUID kSystemTraceControlGuid =
{ 0x9e814aad, 0x3204, 0x11d2,
  { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

namespace
{
constexpr auto kDownloadsScanInterval = std::chrono::milliseconds(750);

std::wstring ReadWideEnvironmentVariable(const wchar_t* name)
{
    if (!name || name[0] == L'\0')
    {
        return {};
    }

    DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0)
    {
        return {};
    }

    std::wstring value(static_cast<std::size_t>(required - 1), L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0 || written >= required)
    {
        return {};
    }

    return value;
}

std::filesystem::path ResolveKnownFolderPath(const KNOWNFOLDERID& folderId)
{
    PWSTR pathBuffer = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, nullptr, &pathBuffer);

    std::filesystem::path result;
    if (SUCCEEDED(hr) && pathBuffer && pathBuffer[0] != L'\0')
    {
        result = pathBuffer;
    }

    if (pathBuffer)
    {
        CoTaskMemFree(pathBuffer);
    }

    return result;
}

std::filesystem::path ResolveUserProfileFallback(const wchar_t* leafName)
{
    const std::wstring userProfile = ReadWideEnvironmentVariable(L"USERPROFILE");
    if (userProfile.empty())
    {
        return {};
    }

    std::filesystem::path path(userProfile);
    if (leafName && leafName[0] != L'\0')
    {
        path /= leafName;
    }

    return path;
}

std::wstring NormalizePath(const std::filesystem::path& path)
{
    std::filesystem::path normalized = path.lexically_normal();
    normalized.make_preferred();
    return normalized.wstring();
}

bool EqualsInsensitive(const std::wstring_view lhs, const std::wstring_view rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        if (std::towlower(lhs[i]) != std::towlower(rhs[i]))
        {
            return false;
        }
    }

    return true;
}

bool ShouldIgnoreDownloadPath(const std::filesystem::path& path)
{
    const std::wstring filename = path.filename().wstring();
    return EqualsInsensitive(filename, L"desktop.ini")
        || EqualsInsensitive(filename, L"Thumbs.db");
}

void AddResolvedRoot(
    std::vector<std::filesystem::path>& roots,
    std::unordered_set<std::wstring>& seenRoots,
    std::filesystem::path candidate)
{
    if (candidate.empty())
    {
        return;
    }

    std::error_code ec;
    const auto absolutePath = std::filesystem::absolute(candidate, ec);
    if (!ec && !absolutePath.empty())
    {
        candidate = absolutePath;
    }

    const auto status = std::filesystem::status(candidate, ec);
    if (ec || !std::filesystem::is_directory(status))
    {
        return;
    }

    const std::wstring normalized = NormalizePath(candidate);
    if (normalized.empty() || !seenRoots.insert(normalized).second)
    {
        return;
    }

    roots.push_back(std::move(candidate));
}

std::vector<std::filesystem::path> ResolveDownloadRoots()
{
    std::vector<std::filesystem::path> roots;
    std::unordered_set<std::wstring> seenRoots;

    AddResolvedRoot(
        roots,
        seenRoots,
        ResolveKnownFolderPath(FOLDERID_Downloads).empty()
            ? ResolveUserProfileFallback(L"Downloads")
            : ResolveKnownFolderPath(FOLDERID_Downloads));

    AddResolvedRoot(
        roots,
        seenRoots,
        ResolveKnownFolderPath(FOLDERID_Desktop).empty()
            ? ResolveUserProfileFallback(L"Desktop")
            : ResolveKnownFolderPath(FOLDERID_Desktop));

    return roots;
}

WindowsDownloadSnapshot BuildDownloadSnapshot(const std::vector<std::filesystem::path>& roots)
{
    WindowsDownloadSnapshot snapshot;

    for (const auto& root : roots)
    {
        if (root.empty())
        {
            continue;
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(root, ec);
        if (ec || !exists)
        {
            continue;
        }

        std::filesystem::recursive_directory_iterator it(
            root,
            std::filesystem::directory_options::skip_permission_denied,
            ec);

        if (ec)
        {
            continue;
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

            WindowsDownloadFileState state{};
            state.size = size;
            state.writeTime = writeTime;
            snapshot.emplace(NormalizePath(entry.path()), std::move(state));

            it.increment(ec);
            if (ec)
            {
                ec.clear();
            }
        }
    }

    return snapshot;
}
} // namespace

WindowsEtwEventCollector* WindowsEtwEventCollector::s_instance = nullptr;

WindowsEtwEventCollector::WindowsEtwEventCollector() = default;

WindowsEtwEventCollector::~WindowsEtwEventCollector()
{
    Stop();
}

bool WindowsEtwEventCollector::Start(OnProcessStart cb)
{
    if (m_running.load())
    {
        return true;
    }

    m_onProcessStart = std::move(cb);
    m_downloadRoots = ResolveDownloadRoots();
    m_downloadSnapshot = BuildDownloadSnapshot(m_downloadRoots);
    m_running.store(true);

    s_instance = this;

    try
    {
        if (m_onDownloadActivity && !m_downloadRoots.empty())
        {
            m_downloadThread = std::thread(&WindowsEtwEventCollector::PollDownloads, this);
        }

        m_thread = std::thread(&WindowsEtwEventCollector::Run, this);
    }
    catch (...)
    {
        m_running.store(false);

        if (m_downloadThread.joinable())
        {
            m_downloadThread.join();
        }

        m_downloadRoots.clear();
        m_downloadSnapshot.clear();
        m_onProcessStart = {};
        s_instance = nullptr;
        return false;
    }

    return true;
}

void WindowsEtwEventCollector::SetOnDownloadActivity(OnDownloadActivity cb)
{
    m_onDownloadActivity = std::move(cb);
}

void WindowsEtwEventCollector::Stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
    }

    if (m_startedSession && m_sessionHandle != 0)
    {
        const ULONG kMaxStr = MAX_PATH;
        const ULONG bufferSize =
            sizeof(EVENT_TRACE_PROPERTIES) +
            (kMaxStr * sizeof(wchar_t)) +
            (kMaxStr * sizeof(wchar_t));

        auto props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(bufferSize));
        if (props)
        {
            ZeroMemory(props, bufferSize);

            props->Wnode.BufferSize = bufferSize;
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            props->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + (kMaxStr * sizeof(wchar_t));

            ControlTraceW(m_sessionHandle, L"EDR-Lite-ProcessSession", props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }

        m_sessionHandle = 0;
    }

    if (m_thread.joinable())
    {
        m_thread.join();
    }

    if (m_downloadThread.joinable())
    {
        m_downloadThread.join();
    }

    m_downloadSnapshot.clear();
    m_downloadRoots.clear();

    if (s_instance == this)
    {
        s_instance = nullptr;
    }
}

void WindowsEtwEventCollector::Run()
{
    const wchar_t* sessionName = KERNEL_LOGGER_NAMEW;
    const ULONG kMaxStr = MAX_PATH;

    const ULONG bufferSize =
        sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxStr * sizeof(wchar_t)) +
        (kMaxStr * sizeof(wchar_t));

    auto props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(bufferSize));
    if (!props)
    {
        return;
    }

    auto resetProps = [&]()
    {
        ZeroMemory(props, bufferSize);

        props->Wnode.BufferSize = bufferSize;
        props->Wnode.Guid = kSystemTraceControlGuid;
        props->Wnode.ClientContext = 1;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
        props->FlushTimer = 1;

        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        props->LogFileNameOffset =
            sizeof(EVENT_TRACE_PROPERTIES) + (kMaxStr * sizeof(wchar_t));
    };

    resetProps();
    ULONG status = StartTraceW(&m_sessionHandle, sessionName, props);

    if (status == ERROR_ALREADY_EXISTS)
    {
        resetProps();
        ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

        resetProps();
        status = StartTraceW(&m_sessionHandle, sessionName, props);
    }

    if (status != ERROR_SUCCESS)
    {
        free(props);
        return;
    }

    m_startedSession = true;

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(sessionName);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &WindowsEtwEventCollector::OnEvent;

    m_traceHandle = OpenTraceW(&log);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        free(props);
        return;
    }

    ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
    free(props);
}

void WindowsEtwEventCollector::PollDownloads()
{
    auto lastDownloadsScan = std::chrono::steady_clock::now();

    while (m_running.load())
    {
        if (m_onDownloadActivity && !m_downloadRoots.empty())
        {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastDownloadsScan >= kDownloadsScanInterval)
            {
                WindowsDownloadSnapshot currentSnapshot = BuildDownloadSnapshot(m_downloadRoots);
                const uint64_t nowQpc = static_cast<uint64_t>(now.time_since_epoch().count());

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

                    DownloadFileEvent event{};
                    event.timestampQpc = nowQpc;
                    event.path = path;
                    m_onDownloadActivity(event);
                }

                m_downloadSnapshot = std::move(currentSnapshot);
                lastDownloadsScan = now;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void WINAPI WindowsEtwEventCollector::OnEvent(PEVENT_RECORD pEvent)
{
    auto self = s_instance;
    if (!self || !self->m_running.load())
    {
        return;
    }

    const USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    const UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    if (!(eventId == 0 && opcode == 1))
    {
        return;
    }

    auto infoBuf = GetEventInfoBuffer(pEvent);
    if (infoBuf.empty())
    {
        return;
    }

    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.data());

    ProcessStartEvent evt{};
    evt.timestampQpc = pEvent->EventHeader.TimeStamp.QuadPart;

    auto tryUInt32 = [&](uint32_t& dst, std::initializer_list<PCWSTR> names)
    {
        for (auto name : names)
        {
            if (GetPropertyUInt32(pEvent, info, name, dst))
            {
                return true;
            }
        }
        return false;
    };

    auto tryString = [&](std::wstring& dst, std::initializer_list<PCWSTR> names)
    {
        for (auto name : names)
        {
            if (GetPropertyStringAuto(pEvent, info, name, dst))
            {
                return true;
            }
        }
        return false;
    };

    const bool okPid = tryUInt32(evt.pid, { L"ProcessId", L"ProcessID" });
    const bool okPpid = tryUInt32(evt.ppid, { L"ParentProcessId", L"ParentProcessID", L"ParentId" });
    (void)okPpid;

    if (!okPid)
    {
        return;
    }

    tryString(evt.imagePath, { L"ImageFileName", L"ImageName", L"ProcessName" });
    tryString(evt.commandLine, { L"CommandLine", L"CmdLine", L"ProcessCommandLine" });

    if (self->m_onProcessStart)
    {
        self->m_onProcessStart(evt);
    }
}
