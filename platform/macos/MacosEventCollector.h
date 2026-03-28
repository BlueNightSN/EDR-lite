#pragma once

#include <atomic>
#include <thread>
#include <unordered_set>

#include "../../core/collectors/IEventCollector.h"

class MacosEventCollector final : public IEventCollector
{
public:
    bool Start(OnProcessStart cb) override;
    void Stop() override;
    bool IsRunning() const override { return m_running.load(); }

private:
    void Run();

    std::atomic<bool> m_running{ false };
    OnProcessStart m_onProcessStart;
    std::thread m_worker;
    std::unordered_set<int> m_knownPids;
};
