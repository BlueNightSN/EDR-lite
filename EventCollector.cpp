#include "EventCollector.h"
#include <initializer_list>
#include <Windows.h>
#include <evntrace.h>
#include "TdhHelpers.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib") // we’ll use this later for parsing fields

// Microsoft-Windows-Kernel-Process provider GUID
static const GUID kSystemTraceControlGuid =
{ 0x9e814aad, 0x3204, 0x11d2,
  { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };


EventCollector* EventCollector::s_instance = nullptr;

EventCollector::EventCollector() = default;

EventCollector::~EventCollector()
{
    Stop();
}

bool EventCollector::Start(OnProcessStart cb)
{

    if (m_running.load())
    {
        return true;
    }

    m_onProcessStart = std::move(cb);
    m_running.store(true);
   

    // single instance for callback forwarding
    s_instance = this;

    m_thread = std::thread(&EventCollector::Run, this);
    
    return true;
}

void EventCollector::Stop()
{
    if (!m_running.exchange(false)) {
        return;
    }

    // Closing the trace handle typically causes ProcessTrace to return.
    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
    }

    // Stop session only if we started it
    if (m_startedSession && m_sessionHandle != 0)
    {
        const ULONG kMaxStr = MAX_PATH;

        const ULONG bufferSize =
            sizeof(EVENT_TRACE_PROPERTIES) +
            (kMaxStr * sizeof(wchar_t)) +   // LoggerName
            (kMaxStr * sizeof(wchar_t));    // LogFileName

        auto props = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
        if (props)
        {
            ZeroMemory(props, bufferSize);

            props->Wnode.BufferSize = bufferSize;
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            props->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + (kMaxStr * sizeof(wchar_t));

            ULONG status = ControlTraceW(m_sessionHandle, L"EDR-Lite-ProcessSession", props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        m_sessionHandle = 0;
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }
    if (s_instance == this) {
        s_instance = nullptr;
    }     
}

void EventCollector::Run()
{
    const wchar_t* sessionName = KERNEL_LOGGER_NAMEW; // "NT Kernel Logger"
    const ULONG kMaxStr = MAX_PATH;

    const ULONG bufferSize =
        sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxStr * sizeof(wchar_t)) +   // LoggerName
        (kMaxStr * sizeof(wchar_t));    // LogFileName

    auto props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(bufferSize));
    if (!props)
    {
        return;
    }

    auto resetProps = [&]()
    {
            ZeroMemory(props, bufferSize);

            props->Wnode.BufferSize = bufferSize;
            props->Wnode.Guid = kSystemTraceControlGuid;   // system/kernel logger
            props->Wnode.ClientContext = 1;                // QPC timestamps
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
        ULONG stopStatus = ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

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
    log.EventRecordCallback = &EventCollector::OnEvent;

    m_traceHandle = OpenTraceW(&log);

    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        free(props);
        return;
    }
    ULONG pt = ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
    free(props);
}

void WINAPI EventCollector::OnEvent(PEVENT_RECORD pEvent)
{

    auto self = s_instance;
    if (!self || !self->m_running.load())
        return;

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
                    return true;
            }
            return false;
        };

    auto tryString = [&](std::wstring& dst, std::initializer_list<PCWSTR> names)
        {
            for (auto name : names)
            {
                if (GetPropertyStringAuto(pEvent, info, name, dst))
                    return true;
            }
            return false;
        };

    bool okPid = tryUInt32(evt.pid, { L"ProcessId", L"ProcessID" });
    bool okPpid = tryUInt32(evt.ppid, { L"ParentProcessId", L"ParentProcessID", L"ParentId" });

    std::wstring image;
    std::wstring cmd;

    bool okImage = tryString(image, { L"ImageFileName", L"ImageName", L"ProcessName" });
    bool okCmd = tryString(cmd, { L"CommandLine", L"CmdLine" });



    if (!okPid)
    {
        return;
    }

    evt.imagePath = std::move(image);
    evt.commandLine = std::move(cmd);

    if (self->m_onProcessStart)
        self->m_onProcessStart(evt);
}