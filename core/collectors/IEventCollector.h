#pragma once

#include <functional>

#include "../events/DownloadFileEvent.h"
#include "../events/ProcessStartEvent.h"

class IEventCollector
{
public:
    using OnProcessStart = std::function<void(const ProcessStartEvent&)>;
    using OnDownloadActivity = std::function<void(const DownloadFileEvent&)>;

    virtual ~IEventCollector() = default;

    virtual bool Start(OnProcessStart cb) = 0;
    virtual void Stop() = 0;
    virtual bool IsRunning() const = 0;
    virtual void SetOnDownloadActivity(OnDownloadActivity cb) { (void)cb; }
};
