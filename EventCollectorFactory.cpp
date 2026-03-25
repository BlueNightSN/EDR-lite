#include "EventCollectorFactory.h"

#if defined(_WIN32)
#include "platform/windows/WindowsEtwEventCollector.h"
#elif defined(__APPLE__)
#include "platform/macos/MacosEventCollector.h"
#endif

std::unique_ptr<IEventCollector> CreateEventCollector()
{
#if defined(_WIN32)
    return std::make_unique<WindowsEtwEventCollector>();
#elif defined(__APPLE__)
    return std::make_unique<MacosEventCollector>();
#else
    return nullptr;
#endif
}
