#include "EventCollector.h"
#include <iostream>
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
        return true;

    m_onProcessStart = std::move(cb);
    m_running.store(true);

    // single instance for callback forwarding (v1)
    s_instance = this;

    m_thread = std::thread(&EventCollector::Run, this);
    return true;
}

void EventCollector::Stop()
{
    if (!m_running.exchange(false))
        return;

    // Closing the trace handle typically causes ProcessTrace to return.
    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
    }

    // Stop session only if we started it
    if (m_startedSession && m_sessionHandle != 0)
    {
        const ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t));
        auto props = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
        if (props)
        {
            ZeroMemory(props, bufferSize);
            props->Wnode.BufferSize = bufferSize;
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ControlTraceW(m_sessionHandle, KERNEL_LOGGER_NAME, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        m_sessionHandle = 0;
    }

    if (m_thread.joinable())
        m_thread.join();

    if (s_instance == this)
        s_instance = nullptr;
}

void EventCollector::Run()
{
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;

    const ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(wchar_t));
    auto props = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
    if (!props)
    {
        std::wcerr << L"malloc failed\n";
        return;
    }
    ZeroMemory(props, bufferSize);

    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.Guid = kSystemTraceControlGuid;   // kernel logger control guid
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;  // <-- process start/stop via kernel flags
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&m_sessionHandle, sessionName, props);
    if (status == ERROR_SUCCESS)
        m_startedSession = true;
    else if (status == ERROR_ALREADY_EXISTS)
        m_startedSession = false;
    else
    {
        std::wcerr << L"StartTrace failed: " << status << L"\n";
        free(props);
        return;
    }

    EVENT_TRACE_LOGFILEW log = {};
    log.LoggerName = (LPWSTR)sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &EventCollector::OnEvent;

    m_traceHandle = OpenTraceW(&log);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        std::wcerr << L"OpenTrace failed. GetLastError=" << GetLastError() << L"\n";
        free(props);
        return;
    }

    status = ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
    (void)status;

    free(props);
}

void WINAPI EventCollector::OnEvent(PEVENT_RECORD pEvent)
{
    auto self = s_instance;
    if (!self || !self->m_running.load())
        return;

    const bool isClassic =
        (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0;
    /*if (!isClassic)
        return;*/

    const UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
    if (opcode != 1) // Process Start
        return;

    ProcessStartEvent evt{};
    evt.timestampQpc = pEvent->EventHeader.TimeStamp.QuadPart;
    evt.pid = pEvent->EventHeader.ProcessId;
    // PPID/image/cmdline will come from payload
    // NEW: parse payload
    auto infoBuf = GetEventInfoBuffer(pEvent);
    if (!infoBuf.empty())
    {
        auto info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.data());

        // DEBUG: dump property names
        std::wcout << L"\n=== Properties for this event ===\n";
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            PWSTR name = (PWSTR)((PBYTE)info + info->EventPropertyInfoArray[i].NameOffset);
            std::wcout << L"  - " << name << L"\n";
        }
        std::wcout << L"===============================\n\n";
        // DEBUG

        // Use payload fields (source of truth)
        (void)GetPropertyUInt32(pEvent, info, L"ProcessId", evt.pid);
        (void)GetPropertyUInt32(pEvent, info, L"ParentId", evt.ppid);
        (void)GetPropertyUnicodeString(pEvent, info, L"ImageFileName", evt.imagePath);
        (void)GetPropertyUnicodeString(pEvent, info, L"CommandLine", evt.commandLine);
    }


    if (self->m_onProcessStart)
        self->m_onProcessStart(evt);
}