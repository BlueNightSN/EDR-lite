#include "WindowsEtwEventCollector.h"

#include <initializer_list>

#include "TdhHelpers.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

static const GUID kSystemTraceControlGuid =
{ 0x9e814aad, 0x3204, 0x11d2,
  { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

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
    m_running.store(true);

    s_instance = this;
    m_thread = std::thread(&WindowsEtwEventCollector::Run, this);

    return true;
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

    std::wstring image;
    std::wstring cmd;

    tryString(image, { L"ImageFileName", L"ImageName", L"ProcessName" });
    tryString(cmd, { L"CommandLine", L"CmdLine" });

    if (!okPid)
    {
        return;
    }

    evt.imagePath = std::move(image);
    evt.commandLine = std::move(cmd);

    if (self->m_onProcessStart)
    {
        self->m_onProcessStart(evt);
    }
}
