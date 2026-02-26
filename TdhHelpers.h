#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <vector>

std::vector<BYTE> GetEventInfoBuffer(PEVENT_RECORD evt);

bool GetPropertyUInt32(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO info,
    PCWSTR name,
    uint32_t& out);

bool GetPropertyUnicodeString(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO info,
    PCWSTR name,
    std::wstring& out);

