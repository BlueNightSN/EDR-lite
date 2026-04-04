#pragma once

#include <atomic>
#include <filesystem>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "../../core/collectors/IEventCollector.h"

struct MacosDownloadFileState
{
    uintmax_t size = 0;
    std::filesystem::file_time_type writeTime{};
};

using MacosDownloadSnapshot = std::unordered_map<std::wstring, MacosDownloadFileState>;

class MacosEventCollector final : public IEventCollector
{
public:
    bool Start(OnProcessStart cb) override;
    void Stop() override;
    bool IsRunning() const override { return m_running.load(); }
    void SetOnDownloadActivity(OnDownloadActivity cb) override;

private:
    void Run();
    void PollDownloads();

    std::atomic<bool> m_running{ false };
    OnProcessStart m_onProcessStart;
    OnDownloadActivity m_onDownloadActivity;
    std::thread m_worker;
    std::unordered_set<int> m_knownPids;
    std::filesystem::path m_downloadsPath;
    MacosDownloadSnapshot m_downloadSnapshot;
};
