#include "TdhHelpers.h"
std::vector<BYTE> GetEventInfoBuffer(PEVENT_RECORD evt)
{
    ULONG size = 0;
    TdhGetEventInformation(evt, 0, nullptr, nullptr, &size);

    std::vector<BYTE> buf(size);
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());

    if (TdhGetEventInformation(evt, 0, nullptr, info, &size) != ERROR_SUCCESS)
        return {};

    return buf;
}

bool GetPropertyUInt32(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO,
    const wchar_t* name,
    uint32_t& out)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = sizeof(uint32_t);
    return TdhGetProperty(evt, 0, nullptr, 1, &desc, size, (PBYTE)&out)
        == ERROR_SUCCESS;
}

bool GetPropertyUnicodeString(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO,
    const wchar_t* name,
    std::wstring& out)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(evt, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size == 0)
        return false;

    std::vector<BYTE> buf(size);
    if (TdhGetProperty(evt, 0, nullptr, 1, &desc, size, buf.data()) != ERROR_SUCCESS)
        return false;

    out.assign(reinterpret_cast<wchar_t*>(buf.data()));
    return true;
}
