#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "ProcessStartEvent.h"
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

class IRule
{
public:
    virtual ~IRule() = default;

    virtual const std::wstring& Name() const = 0;
    virtual std::optional<Alert> Evaluate(const ProcessStartEvent& e) const = 0;
};

class Guard
{
private:
    std::vector<std::unique_ptr<IRule>> m_rules;

public:
    void AddRule(std::unique_ptr<IRule> rule);
    bool RemoveRuleByIndex(std::size_t index); // 0-based
    std::vector<Alert> Inspect(const ProcessStartEvent& e) const;
    std::size_t RuleCount() const;
};

