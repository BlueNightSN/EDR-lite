#pragma once

#include <atomic>
#include <filesystem>
#include <thread>
#include <unordered_map>
#include <vector>

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "../../core/collectors/IEventCollector.h"

struct WindowsDownloadFileState
{
    uintmax_t size = 0;
    std::filesystem::file_time_type writeTime{};
};

using WindowsDownloadSnapshot = std::unordered_map<std::wstring, WindowsDownloadFileState>;

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
    void SetOnDownloadActivity(OnDownloadActivity cb) override;

private:
    void Run();
    void PollDownloads();
    static void WINAPI OnEvent(PEVENT_RECORD pEvent);

    std::thread m_thread;
    std::thread m_downloadThread;
    std::atomic<bool> m_running{ false };

    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    bool m_startedSession = false;

    OnProcessStart m_onProcessStart;
    OnDownloadActivity m_onDownloadActivity;
    std::vector<std::filesystem::path> m_downloadRoots;
    WindowsDownloadSnapshot m_downloadSnapshot;

    static WindowsEtwEventCollector* s_instance;
};
