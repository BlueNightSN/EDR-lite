EDR-Lite

EDR-Lite is a lightweight C++17 telemetry collector that captures process start activity and pushes normalized events through a small guard/rule pipeline.

The project currently supports:

- Windows process creation telemetry using ETW and TDH
- macOS process launch telemetry using process snapshot polling

The codebase is organized as a low-risk refactor of the original working implementation. Platform-specific collectors stay isolated, while shared event and guard logic live in a common core layer.

Features

- Real-time Windows process creation monitoring using ETW
- TDH-based ETW property parsing for Windows process events
- macOS process launch monitoring
- Shared `ProcessStartEvent` model across platforms
- Producer-consumer event flow between collector and app runtime
- Simple guard/rule engine for inspection logic
- Compile-time platform backend selection

Folder Layout

```text
app/
  Main.cpp
  Runtime.cpp
  Runtime.h

core/
  collectors/
    EventCollectorFactory.cpp
    EventCollectorFactory.h
    IEventCollector.h
  events/
    ProcessStartEvent.h
  guard/
    Guard.cpp
    Guard.h

platform/
  windows/
    EtwTdhHelpers.cpp
    EtwTdhHelpers.h
    WindowsEtwEventCollector.cpp
    WindowsEtwEventCollector.h
  macos/
    MacosEventCollector.cpp
    MacosEventCollector.h
```

Architecture

The runtime flow is intentionally simple:

```text
Platform Collector
      |
      | ProcessStartEvent
      v
  Event Queue
      |
      v
  Guard Engine
      |
      v
 Alerts / Console Output
```

Layer responsibilities:

- `app/`: application bootstrap, queue loop, stop handling, and console printing
- `core/`: shared event model, collector interface, collector factory, and guard/rule logic
- `platform/windows/`: Windows ETW collection and TDH parsing helpers
- `platform/macos/`: macOS launch collection logic

Platform Backends

Windows

- Uses the NT Kernel Logger / kernel process ETW flow
- Parses event properties with TDH helpers
- Normalizes fields into `ProcessStartEvent`
- Keeps ETW callback and property parsing isolated in the Windows backend

macOS

- Polls active processes and detects newly seen PIDs
- Builds a normalized `ProcessStartEvent` using macOS process APIs
- Keeps launch-monitoring details isolated in the macOS backend

Event Flow

1. A platform collector captures a process start event.
2. The collector normalizes the event into `ProcessStartEvent`.
3. The collector forwards the event through the shared callback interface.
4. The app runtime pushes the event into a thread-safe queue.
5. The consumer loop sends the event to the `Guard`.
6. The app prints the event and alert count.

Core Types

`ProcessStartEvent`

```cpp
struct ProcessStartEvent
{
    uint64_t timestampQpc = 0;
    uint32_t pid = 0;
    uint32_t ppid = 0;

    std::wstring imagePath;
    std::wstring parentImagePath;
    std::wstring commandLine;
};
```

`IEventCollector`

- Common interface implemented by the Windows and macOS collectors
- Exposes `Start`, `Stop`, and `IsRunning`

`Guard`

- Owns a list of `IRule` instances
- Evaluates each `ProcessStartEvent`
- Returns zero or more `Alert` objects

Why ETW on Windows?

ETW provides low-overhead telemetry commonly used by security tooling. In this project it is used specifically for process creation events, which are a useful foundation for higher-level detections.

Building

Windows

Requirements:

- Windows 10 / 11
- Visual Studio 2022
- Windows SDK

Relevant system libraries:

- `advapi32.lib`
- `tdh.lib`

Build the Visual Studio project in x64 configuration.

macOS

The project also builds on macOS with a C++17 compiler and the platform system headers used by `libproc` and `sysctl`.
