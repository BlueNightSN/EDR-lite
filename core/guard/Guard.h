#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../events/ProcessStartEvent.h"

enum class Severity
{
    Info,
    Low,
    Medium,
    High
};

struct Alert
{
    Severity severity = Severity::Info;
    std::wstring ruleName;
    std::wstring message;

    uint32_t pid = 0;
};

enum class DownloadScanOutcome
{
    Clean,
    Malicious,
    Unknown,
    Error
};

struct DownloadScanResult
{
    std::wstring path;
    DownloadScanOutcome outcome = DownloadScanOutcome::Unknown;
    std::string sha256;
    bool virusTotalQueried = false;
    std::wstring status;
    int maliciousCount = 0;
    int suspiciousCount = 0;
};

class IRule
{
public:
    virtual ~IRule() = default;

    virtual const std::wstring& Name() const = 0;
    virtual bool Evaluate(const ProcessStartEvent& e, Alert& alert) const = 0;
};

class Guard
{
public:
    using OnDownloadScanResult = std::function<void(const DownloadScanResult&)>;

private:
    struct DownloadScanState;
    std::vector<std::unique_ptr<IRule>> m_rules;
    std::unique_ptr<DownloadScanState> m_downloadScan;

public:
    Guard();
    ~Guard();
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    Guard(Guard&&) = delete;
    Guard& operator=(Guard&&) = delete;

    void AddRule(std::unique_ptr<IRule> rule);
    bool RemoveRuleByIndex(std::size_t index); // 0-based
    std::vector<Alert> Inspect(const ProcessStartEvent& e) const;
    void InspectDownloadPath(const std::wstring& path);
    void SetOnDownloadScanResult(OnDownloadScanResult cb);
    std::size_t RuleCount() const;
};
