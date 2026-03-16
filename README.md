EDR-Lite

A lightweight Endpoint Detection telemetry collector written in C++ that monitors Windows process creation events using ETW (Event Tracing for Windows).

This project is a learning and research implementation of the type of telemetry pipelines used inside modern Endpoint Detection & Response (EDR) systems.

It captures process start events from the Windows kernel, parses event properties using TDH, and feeds them through a small rule engine for inspection.

Features

• Real-time process creation monitoring using Windows ETW
• Uses the NT Kernel Logger provider
• TDH property parsing to extract event fields
• Producer–consumer architecture to safely process events
• Simple Guard rule engine for detection logic
• Clean modular C++ design

Architecture

The system follows a simple telemetry pipeline similar to those used in security agents.

Windows Kernel
      │
      │ ETW Events
      ▼
+-------------------+
| EventCollector    |
| (ETW consumer)    |
+-------------------+
          │
          │ ProcessStartEvent
          ▼
+-------------------+
| Event Queue       |
| (producer/consumer)
+-------------------+
          │
          ▼
+-------------------+
| Guard Engine      |
| (rule evaluation) |
+-------------------+
          │
          ▼
+-------------------+
| Alerts / Output   |
+-------------------+
Event Flow

1.Windows kernel emits process start ETW events

2.EventCollector subscribes to the NT Kernel Logger

3.The ETW callback parses raw events using TDH

4.Events are normalized into ProcessStartEvent

5.Events are pushed into a thread-safe queue

6.The consumer thread sends them to the Guard engine

7.Rules evaluate the event and may generate alerts

Example Output
PID=8344 PPID=7020 Image=C:\Windows\System32\notepad.exe Alerts=0
PID=9212 PPID=7020 Image=C:\Windows\System32\cmd.exe Alerts=0
Technologies Used

C++17

Windows ETW (Event Tracing for Windows)

TDH (Trace Data Helper API)

Win32 API

Multithreading (std::thread)

Synchronization primitives (mutex, condition_variable)

Modern C++ containers and RAII

Key Components
EventCollector

Responsible for:

Starting the NT Kernel Logger ETW session

Receiving raw ETW events

Parsing event properties using TDH

Converting events into ProcessStartEvent objects

ProcessStartEvent

Normalized event structure used throughout the pipeline.

struct ProcessStartEvent
{
    uint64_t timestampQpc;
    uint32_t pid;
    uint32_t ppid;

    std::wstring imagePath;
    std::wstring commandLine;
};
Guard Engine

The Guard component evaluates events using a rule system.

Rules implement a simple interface:

IRule
   └── Evaluate(ProcessStartEvent)

Each rule may return an Alert if suspicious behavior is detected.

Why ETW?

ETW provides low-overhead kernel telemetry used by many Windows security products.

It allows monitoring:

process creation

file access

network activity

registry events

PowerShell activity

This project focuses on process start telemetry, which is the foundation for many detection rules.

Building

Requirements:

Windows 10 / 11

Visual Studio 2022

Windows SDK

TDH / ETW libraries

Libraries used:

advapi32.lib
tdh.lib
Rpcrt4.lib

Build the project using Visual Studio x64 configuration.
