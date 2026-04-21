#include "ProcessTracker.h"

void ProcessTracker::ObserveProcessStart(const ProcessStartEvent& event)
{
    const auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(m_mutex);
    auto [it, inserted] = m_processes.try_emplace(event.pid);
    ProcessState& state = it->second;

    if (inserted)
    {
        state.pid = event.pid;
        state.firstSeen = now;
    }

    state.ppid = event.ppid;
    state.imagePath = event.imagePath;
    state.parentImagePath = event.parentImagePath;
    state.commandLine = event.commandLine;
    state.lastSeen = now;
}

std::optional<ProcessState> ProcessTracker::TryGet(uint32_t pid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_processes.find(pid);
    if (it == m_processes.end())
    {
        return std::nullopt;
    }

    return it->second;
}

std::vector<ProcessState> ProcessTracker::Snapshot() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ProcessState> snapshot;
    snapshot.reserve(m_processes.size());

    for (const auto& [_, state] : m_processes)
    {
        snapshot.push_back(state);
    }

    return snapshot;
}

std::size_t ProcessTracker::Size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_processes.size();
}

