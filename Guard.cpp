#include "Guard.h"

void Guard::AddRule(std::unique_ptr<IRule> rule)
{
    if (!rule) return;
    m_rules.push_back(std::move(rule));
}

bool Guard::RemoveRuleByIndex(std::size_t index)
{
    if (index >= m_rules.size())
        return false;

    m_rules.erase(m_rules.begin() + static_cast<std::ptrdiff_t>(index));
    return true;
}

std::vector<Alert> Guard::Inspect(const ProcessStartEvent& e) const
{
    std::vector<Alert> alerts;

    for (const auto& rule : m_rules)
    {
        if (!rule) continue;

        std::optional<Alert> alert = rule->Evaluate(e);
        if (alert)
            alerts.push_back(*alert);
    }

    return alerts;
}

std::size_t Guard::RuleCount() const
{
    return m_rules.size();
}
