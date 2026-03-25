#pragma once

#include <functional>

#include "ProcessStartEvent.h"

class IEventCollector
{
public:
    using OnProcessStart = std::function<void(const ProcessStartEvent&)>;

    virtual ~IEventCollector() = default;

    virtual bool Start(OnProcessStart cb) = 0;
    virtual void Stop() = 0;
    virtual bool IsRunning() const = 0;
};
