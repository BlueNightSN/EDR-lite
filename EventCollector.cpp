#include "EventCollector.h"
#include <iostream>
#include <initializer_list>
#include <Windows.h>
#include <evntrace.h>
#include "TdhHelpers.h"
#include <rpc.h>
#include <evntcons.h>
#include <iomanip>
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib") // we’ll use this later for parsing fields

// Microsoft-Windows-Kernel-Process provider GUID
static const GUID kSystemTraceControlGuid =
{ 0x9e814aad, 0x3204, 0x11d2,
  { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

// Microsoft-Windows-Kernel-Process event provider GUID
static const GUID kKernelProcessProviderGuid =
{ 0x3d6fa8d0, 0xfe05, 0x11d0,
  { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };

EventCollector* EventCollector::s_instance = nullptr;

EventCollector::EventCollector() = default;

EventCollector::~EventCollector()
{
    Stop();
}

bool EventCollector::Start(OnProcessStart cb)
{
    std::wcout << L"[Start] entered\n";

    if (m_running.load())
    {
        std::wcout << L"[Start] already running\n";
        return true;
    }

    m_onProcessStart = std::move(cb);
    m_running.store(true);
    std::wcout << L"[Start] m_running set to true\n";

    // single instance for callback forwarding (v1)
    s_instance = this;
    std::wcout << L"[Start] s_instance set\n";

    m_thread = std::thread(&EventCollector::Run, this);
    std::wcout << L"[Start] worker thread launched\n";
    
    return true;
}

void EventCollector::Stop()
{
    std::wcout << L"[Stop] entered\n";

    if (!m_running.exchange(false)) {
        std::wcout << L"[Stop] already not running, returning\n";
        return;
    }

    std::wcout << L"[Stop] m_running switched to false\n";

    // Closing the trace handle typically causes ProcessTrace to return.
    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        std::wcout << L"[Stop] closing trace handle\n";
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
        std::wcout << L"[Stop] trace handle closed\n";
    }

    // Stop session only if we started it
    if (m_startedSession && m_sessionHandle != 0)
    {
        std::wcout << L"[Stop] stopping ETW session\n";

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

            ULONG status = ControlTraceW(m_sessionHandle,
                L"EDR-Lite-ProcessSession",
                props,
                EVENT_TRACE_CONTROL_STOP);
            std::wcout << L"[Stop] ControlTraceW status=" << status << L"\n";

            free(props);
        }
        else {
            std::wcout << L"[Stop] malloc for props failed\n";
        }
        m_sessionHandle = 0;
    }

    if (m_thread.joinable()) {
        std::wcout << L"[Stop] joining worker thread...\n";
        m_thread.join();
        std::wcout << L"[Stop] worker thread joined\n";
    }
        

    if (s_instance == this) {
        s_instance = nullptr;
        std::wcout << L"[Stop] clearing s_instance\n";
    }
    std::wcout << L"[Stop] finished\n";
        
}

void EventCollector::Run()
{
    std::wcout << L"[Run] entered\n";

    const wchar_t* sessionName = KERNEL_LOGGER_NAMEW; // "NT Kernel Logger"
    const ULONG kMaxStr = MAX_PATH;

    const ULONG bufferSize =
        sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxStr * sizeof(wchar_t)) +   // LoggerName
        (kMaxStr * sizeof(wchar_t));    // LogFileName

    auto props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(bufferSize));
    if (!props)
    {
        std::wcerr << L"[Run] malloc failed\n";
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

    std::wcout << L"[Run] calling StartTraceW(kernel logger)...\n";
    ULONG status = StartTraceW(&m_sessionHandle, sessionName, props);
    std::wcout << L"[Run] StartTraceW status=" << status << L"\n";

    if (status == ERROR_ALREADY_EXISTS)
    {
        std::wcout << L"[Run] kernel logger already exists, stopping old one...\n";

        resetProps();
        ULONG stopStatus = ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        std::wcout << L"[Run] ControlTraceW(stop old) status=" << stopStatus << L"\n";

        resetProps();
        status = StartTraceW(&m_sessionHandle, sessionName, props);
        std::wcout << L"[Run] StartTraceW(after stop) status=" << status << L"\n";
    }

    if (status != ERROR_SUCCESS)
    {
        std::wcerr << L"[Run] StartTraceW failed: " << status << L"\n";
        free(props);
        return;
    }

    m_startedSession = true;
    std::wcout << L"[Run] kernel session started: " << sessionName << L"\n";

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(sessionName);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &EventCollector::OnEvent;

    std::wcout << L"[Run] calling OpenTraceW...\n";
    m_traceHandle = OpenTraceW(&log);
    std::wcout << L"[Run] OpenTraceW handle=" << m_traceHandle << L"\n";

    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        std::wcerr << L"[Run] OpenTraceW failed. GetLastError=" << GetLastError() << L"\n";
        free(props);
        return;
    }

    std::wcout << L"[Run] calling ProcessTrace...\n";
    ULONG pt = ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
    std::wcout << L"[Run] ProcessTrace returned status=" << pt << L"\n";

    free(props);
    std::wcout << L"[Run] exiting\n";
}

static void PrintGuid(const GUID& guid);

void WINAPI EventCollector::OnEvent(PEVENT_RECORD pEvent)
{
    auto self = s_instance;
    if (!self || !self->m_running.load())
        return;

    const USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    const UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    std::wcout << L"[RAW] id=" << eventId
        << L" opcode=" << static_cast<unsigned>(opcode)
        << L" pid(header)=" << pEvent->EventHeader.ProcessId
        << L" provider=";
    PrintGuid(pEvent->EventHeader.ProviderId);
    std::wcout << L"\n";

    
    if (eventId != 1 && eventId != 2)
    {
        std::wcout << L"[OnEvent] ignored: event id is not 1/2\n";
        return;
    }

    auto infoBuf = GetEventInfoBuffer(pEvent);
    if (infoBuf.empty())
    {
        std::wcout << L"[OnEvent] infoBuf empty\n";
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

    std::wcout << L"[OnEvent] id=" << eventId
        << L" opcode=" << static_cast<unsigned>(opcode)
        << L" okPid=" << okPid
        << L" okPpid=" << okPpid
        << L" okImage=" << okImage
        << L" okCmd=" << okCmd
        << L" image=\"" << (image.empty() ? L"<empty>" : image.c_str()) << L"\""
        << L" cmd=\"" << (cmd.empty() ? L"<empty>" : cmd.c_str()) << L"\""
        << L"\n";

    if (!okPid)
    {
        std::wcout << L"[OnEvent] rejected: no pid\n";
        return;
    }

    evt.imagePath = std::move(image);
    evt.commandLine = std::move(cmd);

    std::wcout << L"[OnEvent] emitting process event\n";

    if (self->m_onProcessStart)
        self->m_onProcessStart(evt);
}


static void PrintGuid(const GUID& guid)
{
    std::wcout
        << std::hex << std::setfill(L'0')
        << L"{"
        << std::setw(8) << guid.Data1 << L"-"
        << std::setw(4) << guid.Data2 << L"-"
        << std::setw(4) << guid.Data3 << L"-"
        << std::setw(2) << static_cast<unsigned>(guid.Data4[0])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[1]) << L"-"
        << std::setw(2) << static_cast<unsigned>(guid.Data4[2])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[3])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[4])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[5])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[6])
        << std::setw(2) << static_cast<unsigned>(guid.Data4[7])
        << L"}"
        << std::dec;
}