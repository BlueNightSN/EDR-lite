#include "EventCollector.h"
#include <iostream>
#include <Windows.h>
#include <evntrace.h>
#include "TdhHelpers.h"
#include <rpc.h>
#include <evntcons.h>
#pragma comment(lib, "Rpcrt4.lib")
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

            ControlTraceW(m_sessionHandle,
                L"EDR-Lite-ProcessSession",
                props,
                EVENT_TRACE_CONTROL_STOP);

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
    const wchar_t* sessionName = L"EDR-Lite-ProcessSession";
    const ULONG kMaxStr = MAX_PATH;

    const ULONG bufferSize =
        sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxStr * sizeof(wchar_t)) +   // LoggerName
        (kMaxStr * sizeof(wchar_t));    // LogFileName

    auto props = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);
    if (!props)
    {
        std::wcerr << L"malloc failed\n";
        return;
    }

    auto resetProps = [&]()
        {
            ZeroMemory(props, bufferSize);

            props->Wnode.BufferSize = bufferSize;
            props->Wnode.ClientContext = 1;            // QPC timestamps
            props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

            // For named private sessions, GUID can be anything stable enough.
            // Using a generated one is fine.
            UuidCreate(&props->Wnode.Guid);

            props->LogFileMode =
                EVENT_TRACE_REAL_TIME_MODE |
                EVENT_TRACE_INDEPENDENT_SESSION_MODE;  // <-- critical for kernel provider delivery

            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (kMaxStr * sizeof(wchar_t));
        };

    resetProps();

    ULONG status = StartTraceW(&m_sessionHandle, sessionName, props);

    if (status == ERROR_ALREADY_EXISTS)
    {
        // IMPORTANT: StartTrace/ControlTrace can mutate the props buffer -> reset before reuse
        resetProps();
        (void)ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

        resetProps();
        status = StartTraceW(&m_sessionHandle, sessionName, props);
    }

    if (status != ERROR_SUCCESS)
    {
        std::wcerr << L"StartTrace failed: " << status << L"\n";
        free(props);
        return;
    }

    m_startedSession = true;
    std::wcout << L"Session started: " << sessionName << L"\n";

    // Enable Microsoft-Windows-Kernel-Process provider on THIS session
    static const GUID kKernelProcessProvider =
    { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    // 0x10 = WINEVENT_KEYWORD_PROCESS (this is what actually turns on process start/stop)
    const ULONGLONG kProcessKeyword = 0x10;

    ULONG en = EnableTraceEx2(
        m_sessionHandle,
        &kKernelProcessProvider,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        kProcessKeyword,   // MatchAnyKeyword
        0,                 // MatchAllKeyword
        0,
        &params);

    std::wcout << L"EnableTraceEx2(Kernel-Process) status=" << en << L"\n";
    if (en != ERROR_SUCCESS)
    {
        std::wcerr << L"EnableTraceEx2 failed: " << en << L"\n";
        free(props);
        return;
    }

    EVENT_TRACE_LOGFILEW log{};
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

    (void)ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);

    free(props);
}

void WINAPI EventCollector::OnEvent(PEVENT_RECORD pEvent)
{
    auto self = s_instance;
    if (!self || !self->m_running.load())
        return;

    // Provider: Microsoft-Windows-Kernel-Process
    static const GUID kKernelProcessProvider =
    { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

    if (pEvent->EventHeader.ProviderId != kKernelProcessProvider)
        return;

    // Parse event metadata (TDH)
    auto infoBuf = GetEventInfoBuffer(pEvent);
    if (infoBuf.empty())
        return;

    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.data());

    // Try extracting the fields we care about.
    ProcessStartEvent evt{};
    evt.timestampQpc = pEvent->EventHeader.TimeStamp.QuadPart;

    bool okPid = GetPropertyUInt32(pEvent, info, L"ProcessId", evt.pid);
    bool okPpid = GetPropertyUInt32(pEvent, info, L"ParentId", evt.ppid);

    std::wstring image;
    std::wstring cmd;

    bool okImage = GetPropertyStringAuto(pEvent, info, L"ImageFileName", image);
    bool okCmd = GetPropertyStringAuto(pEvent, info, L"CommandLine", cmd);

    // Only treat as "ProcessStart event" if it actually has process-ish fields.
    // (This avoids hardcoding EventDescriptor.Id which varies in practice.)
    if (!okPid || (!okImage && !okCmd))
        return;

    evt.imagePath = std::move(image);
    evt.commandLine = std::move(cmd);

    if (self->m_onProcessStart)
        self->m_onProcessStart(evt);
}