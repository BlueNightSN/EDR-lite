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
    void Run();
    static void WINAPI OnEvent(PEVENT_RECORD pEvent);

    std::thread m_thread;
    std::atomic<bool> m_running{ false };

    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;

    bool m_startedSession = false;

    OnProcessStart m_onProcessStart;

    // since ETW callback is static, we keep a single active instance
    static EventCollector* s_instance;
};

