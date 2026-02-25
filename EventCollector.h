#pragma once
#include <functional>
#include <thread>
#include <atomic>
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "ProcessStartEvent.h"
class EventCollector
{
public:
    using OnProcessStart = std::function<void(const ProcessStartEvent&)>;

    EventCollector();
    ~EventCollector();

    EventCollector(const EventCollector&) = delete;
    EventCollector& operator=(const EventCollector&) = delete;
    EventCollector(EventCollector&&) = delete;
    EventCollector& operator=(EventCollector&&) = delete;

    // Start collecting process-start events
    bool Start(OnProcessStart cb);

    // Stop collecting
    void Stop();

    bool IsRunning() const { return m_running.load(); }

private:
    // ETW worker
    void Run();

    // ETW callback
    static void WINAPI OnEvent(PEVENT_RECORD pEvent);

    
    std::thread m_thread;
    std::atomic<bool> m_running{ false };

    // ETW handles
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;

    // Did we create the kernel session ourselves?
    bool m_startedSession = false;

    // user callback
    OnProcessStart m_onProcessStart;

    // since ETW callback is static, we keep a single active instance (fine for v1)
    static EventCollector* s_instance;
};

