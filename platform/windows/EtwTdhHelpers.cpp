#include "EtwTdhHelpers.h"

#include <cwchar>

std::vector<BYTE> GetEventInfoBuffer(PEVENT_RECORD evt)
{
    ULONG size = 0;
    TdhGetEventInformation(evt, 0, nullptr, nullptr, &size);

    std::vector<BYTE> buf(size);
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());

    if (TdhGetEventInformation(evt, 0, nullptr, info, &size) != ERROR_SUCCESS)
    {
        return {};
    }

    return buf;
}

bool GetPropertyUInt32(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO,
    PCWSTR name,
    uint32_t& out)
{
    out = 0;

    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(const_cast<PWSTR>(name));
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = sizeof(uint32_t);
    return TdhGetProperty(evt, 0, nullptr, 1, &desc, size, reinterpret_cast<PBYTE>(&out)) == ERROR_SUCCESS;
}

static bool FindTopLevelPropertyIndex(
    PTRACE_EVENT_INFO info,
    const wchar_t* name,
    ULONG& outIndex)
{
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
    {
        const auto& pi = info->EventPropertyInfoArray[i];
        auto propName = reinterpret_cast<PCWSTR>(reinterpret_cast<PBYTE>(info) + pi.NameOffset);
        if (propName && wcscmp(propName, name) == 0)
        {
            outIndex = i;
            return true;
        }
    }

    return false;
}

bool GetPropertyUnicodeString(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO info,
    PCWSTR name,
    std::wstring& out)
{
    out.clear();

    ULONG index = 0;
    if (!FindTopLevelPropertyIndex(info, name, index))
    {
        return false;
    }

    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(const_cast<PWSTR>(name));
    desc.ArrayIndex = ULONG_MAX;

    ULONG propLen = 0;
    if (TdhGetPropertySize(evt, 0, nullptr, 1, &desc, &propLen) != ERROR_SUCCESS || propLen == 0)
    {
        return false;
    }

    const auto& epi = info->EventPropertyInfoArray[index];
    const USHORT inType = epi.nonStructType.InType;
    const USHORT outType = epi.nonStructType.OutType;

    const ULONG pointerSize = (evt->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4u : 8u;

    ULONG bufSize = 0;
    USHORT userDataConsumed = 0;

    TDHSTATUS st = TdhFormatProperty(
        info,
        nullptr,
        pointerSize,
        inType,
        outType,
        static_cast<USHORT>(propLen),
        static_cast<USHORT>(evt->UserDataLength),
        reinterpret_cast<PBYTE>(evt->UserData),
        &bufSize,
        nullptr,
        &userDataConsumed);

    if (st != ERROR_SUCCESS || bufSize == 0)
    {
        return false;
    }

    std::vector<WCHAR> buf(bufSize);

    st = TdhFormatProperty(
        info,
        nullptr,
        pointerSize,
        inType,
        outType,
        static_cast<USHORT>(propLen),
        static_cast<USHORT>(evt->UserDataLength),
        reinterpret_cast<PBYTE>(evt->UserData),
        &bufSize,
        buf.data(),
        &userDataConsumed);

    if (st != ERROR_SUCCESS)
    {
        return false;
    }

    out.assign(buf.data());
    return !out.empty();
}

static std::wstring AnsiToWide(const char* s)
{
    if (!s)
    {
        return L"";
    }

    int needed = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (needed <= 1)
    {
        return L"";
    }

    std::wstring w(static_cast<std::size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, &w[0], needed);
    return w;
}

bool GetPropertyStringAuto(
    PEVENT_RECORD evt,
    PTRACE_EVENT_INFO info,
    PCWSTR name,
    std::wstring& out)
{
    out.clear();

    if (!evt || !info || !name)
    {
        return false;
    }

    ULONG index = 0;
    if (!FindTopLevelPropertyIndex(info, name, index))
    {
        return false;
    }

    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(const_cast<PWSTR>(name));
    desc.ArrayIndex = ULONG_MAX;

    ULONG rawSize = 0;
    if (TdhGetPropertySize(evt, 0, nullptr, 1, &desc, &rawSize) != ERROR_SUCCESS || rawSize == 0)
    {
        return false;
    }

    std::vector<BYTE> buf(rawSize);
    if (TdhGetProperty(evt, 0, nullptr, 1, &desc, rawSize, buf.data()) != ERROR_SUCCESS)
    {
        return false;
    }

    const auto& epi = info->EventPropertyInfoArray[index];
    const USHORT inType = epi.nonStructType.InType;

    if (inType == TDH_INTYPE_UNICODESTRING)
    {
        const auto* ws = reinterpret_cast<const wchar_t*>(buf.data());
        std::size_t cch = rawSize / sizeof(wchar_t);

        while (cch > 0 && ws[cch - 1] == L'\0')
        {
            cch--;
        }

        out.assign(ws, ws + cch);
        return !out.empty();
    }

    if (inType == TDH_INTYPE_ANSISTRING)
    {
        if (buf.back() != 0)
        {
            buf.push_back(0);
        }

        const auto* s = reinterpret_cast<const char*>(buf.data());
        out = AnsiToWide(s);
        return !out.empty();
    }

    return false;
}
