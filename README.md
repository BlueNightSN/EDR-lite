EDR-Lite
========

EDR-Lite is a lightweight C++17 endpoint telemetry prototype. It captures
process start activity, watches common download locations for changed files,
and forwards normalized events through a small guard pipeline.

The project currently supports:

- Windows process creation telemetry using ETW and TDH
- Windows download/desktop file activity polling
- macOS process launch telemetry using process snapshot polling
- macOS Downloads folder activity polling
- Optional VirusTotal file reputation scanning for stable downloaded files

Features
--------

- Real-time Windows process creation monitoring using ETW
- TDH-based ETW property parsing helpers for Windows process events
- macOS process launch monitoring with `libproc` and `sysctl`
- Shared `ProcessStartEvent` model across platforms
- Shared `DownloadFileEvent` model for file activity
- Producer-consumer event flow between collectors and app runtime
- File stability delay before scanning changed download candidates
- Background VirusTotal lookup/upload flow for downloaded files
- 24-hour local VirusTotal verdict cache
- Simple guard/rule engine for inspection logic
- Compile-time platform backend selection

Folder Layout
-------------

```text
app/
  DownloadCandidateTracker.cpp
  DownloadCandidateTracker.h
  Main.cpp
  Runtime.cpp
  Runtime.h

core/
  collectors/
    EventCollectorFactory.cpp
    EventCollectorFactory.h
    IEventCollector.h
  config/
    AppConfig.cpp
    AppConfig.h
  events/
    DownloadFileEvent.h
    EventMetadata.h
    ProcessStartEvent.h
  guard/
    Guard.cpp
    Guard.h
  logging/
    Logger.cpp
    Logger.h
  process/
    ProcessTracker.cpp
    ProcessTracker.h

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
------------

The runtime flow is intentionally small:

```text
Platform Collector
      |
      | ProcessStartEvent / DownloadFileEvent
      v
  Event Queues
      |
      v
  Guard Engine
      |
      v
 Alerts / Console Output / Download Scan Logs
```

Layer responsibilities:

- `app/`: application bootstrap, simple event queues, runtime coordination, and download candidate stability tracking
- `core/`: config, structured logging, process state, shared event models, collector interface/factory, and guard/scanning logic
- `platform/windows/`: Windows ETW collection, TDH parsing helpers, and download/desktop polling
- `platform/macos/`: macOS process polling and Downloads folder polling

Phase 1 Architecture
--------------------

The runtime is intentionally thin. It loads configuration, creates the logger,
collector, guard, process tracker, and download candidate tracker, wires their
callbacks, and coordinates shutdown.

Phase 1 components:

- `AppConfig`: compiled defaults plus environment-variable overrides for runtime tunables
- `Logger`: human-readable console logs plus structured JSON lines in a local log file
- `ProcessTracker`: in-memory process state table for future parent/child correlation
- `DownloadCandidateTracker`: file stability and quiet-period handling before guard scanning
- `Guard` scan callback: emits explicit `DownloadScanResult` records for structured logging

The queue flow remains simple and local to `Runtime.cpp`: collector callbacks
enqueue events and notify the runtime loop. Logging and processing happen after
events are drained, not in the collector callback hot path.

Platform Backends
-----------------

### Windows

- Uses the NT Kernel Logger / kernel process ETW flow
- Parses ETW metadata with TDH helpers
- Reads live process image paths for process start events
- Polls the user's Downloads and Desktop folders for changed regular files
- Emits normalized `ProcessStartEvent` and `DownloadFileEvent` objects

Kernel ETW collection usually requires the app to run from an elevated console.

### macOS

- Polls active processes and detects newly seen PIDs
- Reads image paths and command lines with macOS process APIs
- Polls `~/Downloads` for changed regular files
- Emits normalized `ProcessStartEvent` and `DownloadFileEvent` objects

Event Flow
----------

1. A platform collector captures a process start or file activity event.
2. The collector normalizes it into `ProcessStartEvent` or `DownloadFileEvent`.
3. The collector forwards the event through the shared callback interface.
4. The app runtime pushes the event into the matching thread-safe queue.
5. Process events are inspected by the `Guard` and printed with alert counts.
6. Download events are tracked until the file appears stable for a short quiet period.
7. Stable download candidates are sent to the guard's download scanner.
8. The scanner computes SHA-256, checks the local cache, and optionally queries or uploads to VirusTotal.

Core Types
----------

### `ProcessStartEvent`

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

### `DownloadFileEvent`

```cpp
struct DownloadFileEvent
{
    uint64_t timestampQpc = 0;
    std::wstring path;
};
```

### `DownloadScanResult`

```cpp
struct DownloadScanResult
{
    std::wstring path;
    DownloadScanOutcome outcome;
    std::string sha256;
    bool virusTotalQueried;
    std::wstring status;
    int maliciousCount;
    int suspiciousCount;
};
```

### `IEventCollector`

- Common interface implemented by the Windows and macOS collectors
- Exposes `Start`, `Stop`, and `IsRunning`
- Supports optional `SetOnDownloadActivity` callbacks

### `Guard`

- Owns a list of `IRule` instances for process inspection
- Evaluates each `ProcessStartEvent`
- Accepts stable download paths for VirusTotal scanning
- Manages a background download scanner thread and local verdict cache
- Emits `DownloadScanResult` callbacks for structured scan-result logging

Setup
-----

### 1. Runtime config and logging

The app runs with compiled defaults when no config is provided.

Environment overrides:

- `EDR_LITE_DOWNLOAD_POLL_MS`: download maintenance loop interval, default `500`
- `EDR_LITE_DOWNLOAD_QUIET_MS`: stable-file quiet period, default `2000`
- `EDR_LITE_CONSOLE_LOG`: `true`/`false`, default `true`
- `EDR_LITE_FILE_LOG`: `true`/`false`, default `true`
- `EDR_LITE_LOG_FILE`: structured log path, default `logs/edr-lite.jsonl`

Structured logs are JSON lines. The default local log path keeps development
and demos easy to inspect:

```text
logs/edr-lite.jsonl
```

### 2. Configure VirusTotal scanning

VirusTotal scanning is optional. Without an API key, the app still collects
process and download activity, but download reputation checks are skipped.

Create a local `.env` file in the repository root:

```text
VT_API_KEY=your_virustotal_api_key_here
```

You can also set `VT_API_KEY` as an environment variable. Environment variables
take precedence over `.env`.

The scanner stores a local verdict cache at:

- Windows: `%LOCALAPPDATA%\EDR-lite\virustotal_cache.tsv`
- macOS: `~/Library/Application Support/EDR-lite/virustotal_cache.tsv`

Files larger than 32 MB are not automatically uploaded when VirusTotal does not
already know the hash.

### 3. Build on Windows

Requirements:

- Windows 10 or 11
- Visual Studio 2022
- Windows SDK

Relevant libraries used by the current code:

- `advapi32.lib`
- `tdh.lib`
- `winhttp.lib`
- Visual Studio default system libraries such as `shell32.lib` and `ole32.lib`

Build the Visual Studio solution in the `x64` configuration:

```powershell
msbuild EDR-lite.sln /p:Configuration=Debug /p:Platform=x64
```

If `msbuild` is not on `PATH`, use the Visual Studio MSBuild executable, for
example:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" EDR-lite.sln /p:Configuration=Debug /p:Platform=x64
```

Run the built executable from an elevated console for ETW process telemetry:

```powershell
.\x64\Debug\EDR-lite.exe
```

Press Enter to stop when running interactively.

### 4. Build on macOS

The macOS backend sources are present, but this repository currently does not
include a macOS project file or build script.

To build the macOS code manually, use a C++17 compiler with the platform headers
for `libproc` and `sysctl`, and link with libcurl for VirusTotal HTTP requests.

Why ETW on Windows?
-------------------

ETW provides low-overhead telemetry commonly used by security tooling. In this
project it is used specifically for process creation events, which are a useful
foundation for higher-level detections.
