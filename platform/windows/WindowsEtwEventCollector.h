#pragma once

#include <atomic>
#include <thread>

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "../../core/collectors/IEventCollector.h"

class WindowsEtwEventCollector final : public IEventCollector
{
public:
    WindowsEtwEventCollector();
    ~WindowsEtwEventCollector() override;

    WindowsEtwEventCollector(const WindowsEtwEventCollector&) = delete;
    WindowsEtwEventCollector& operator=(const WindowsEtwEventCollector&) = delete;
    WindowsEtwEventCollector(WindowsEtwEventCollector&&) = delete;
    WindowsEtwEventCollector& operator=(WindowsEtwEventCollector&&) = delete;

    bool Start(OnProcessStart cb) override;
    void Stop() override;
    bool IsRunning() const override { return m_running.load(); }

private:
    void Run();
    static void WINAPI OnEvent(PEVENT_RECORD pEvent);

    std::thread m_thread;
    std::atomic<bool> m_running{ false };

    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    bool m_startedSession = false;

    OnProcessStart m_onProcessStart;

    static WindowsEtwEventCollector* s_instance;
};
