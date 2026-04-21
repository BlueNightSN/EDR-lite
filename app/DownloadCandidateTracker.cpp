#include "DownloadCandidateTracker.h"

#include <cwctype>

#include "../core/logging/Logger.h"

namespace
{
bool ContainsInsensitive(const std::wstring& value, const std::wstring& needle)
{
    if (needle.empty() || value.size() < needle.size())
    {
        return false;
    }

    for (std::size_t i = 0; i <= value.size() - needle.size(); ++i)
    {
        bool matches = true;
        for (std::size_t j = 0; j < needle.size(); ++j)
        {
            if (std::towlower(value[i + j]) != std::towlower(needle[j]))
            {
                matches = false;
                break;
            }
        }

        if (matches)
        {
            return true;
        }
    }

    return false;
}
} // namespace

DownloadCandidateTracker::DownloadCandidateTracker(const AppConfig& config)
    : m_quietPeriod(config.downloadQuietPeriod)
{
}

std::wstring DownloadCandidateTracker::NormalizePathKey(const std::wstring& path)
{
    if (path.empty())
    {
        return {};
    }

    std::filesystem::path normalized(path);
    normalized = normalized.lexically_normal();
    normalized.make_preferred();
    return normalized.wstring();
}

void DownloadCandidateTracker::ObserveDownloadActivity(
    const DownloadFileEvent& event,
    Logger& logger)
{
    const std::wstring key = NormalizePathKey(event.path);
    if (key.empty())
    {
        return;
    }

    if (ContainsInsensitive(key, L"\\logs\\edr-lite"))
    {
        return;
    }

    const TimePoint now = Clock::now();
    auto [it, inserted] = m_candidates.try_emplace(key);
    Candidate& candidate = it->second;

    if (inserted)
    {
        candidate.path = key;
        candidate.firstSeen = now;
    }

    candidate.lastChangeTime = now;
    logger.LogDownloadCandidate(key, inserted ? L"seen" : L"updated");
}

std::vector<std::wstring> DownloadCandidateTracker::CollectStableCandidates(Logger& logger)
{
    std::vector<std::wstring> stablePaths;
    std::error_code ec;
    const TimePoint now = Clock::now();

    for (auto it = m_candidates.begin(); it != m_candidates.end();)
    {
        Candidate& candidate = it->second;
        const std::filesystem::path path(candidate.path);

        if (!std::filesystem::exists(path, ec) || ec)
        {
            ec.clear();
            it = m_candidates.erase(it);
            continue;
        }

        const auto status = std::filesystem::status(path, ec);
        if (ec || !std::filesystem::is_regular_file(status))
        {
            ec.clear();
            it = m_candidates.erase(it);
            continue;
        }

        const uintmax_t currentSize = std::filesystem::file_size(path, ec);
        if (ec)
        {
            ec.clear();
            ++it;
            continue;
        }

        if (!candidate.hasObservedSize)
        {
            candidate.lastObservedSize = currentSize;
            candidate.previousObservedSize = currentSize;
            candidate.hasObservedSize = true;
            ++it;
            continue;
        }

        candidate.previousObservedSize = candidate.lastObservedSize;
        candidate.lastObservedSize = currentSize;

        if (candidate.lastObservedSize != candidate.previousObservedSize)
        {
            candidate.lastChangeTime = now;
            logger.LogDownloadCandidate(candidate.path, L"size_changed");
            ++it;
            continue;
        }

        if (now - candidate.lastChangeTime < m_quietPeriod)
        {
            ++it;
            continue;
        }

        logger.LogStableDownloadCandidate(candidate.path);
        stablePaths.push_back(candidate.path);
        it = m_candidates.erase(it);
    }

    return stablePaths;
}
