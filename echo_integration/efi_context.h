#pragma once
#include "windows_support.h"
#include <optional>
#include <cstring>

namespace echo_integration {
inline std::optional<bool> measured_secure_boot(const std::vector<std::uint8_t>& data) {
    // UEFI_VARIABLE_DATA: global-variable GUID, UINT64 name/data lengths, UTF16 name, data.
    static const std::uint8_t guid[]={0x61,0xdf,0xe4,0x8b,0xca,0x93,0xd2,0x11,0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c};
    if(data.size()<53 || std::memcmp(data.data(),guid,16)) return {};
    std::uint64_t name=0,size=0; std::memcpy(&name,data.data()+16,8);std::memcpy(&size,data.data()+24,8);
    if(name!=10 || size!=1 || data.size()!=53) return {};
    const char* expected="SecureBoot";
    for(std::size_t i=0;i<10;++i) if(data[32+i*2]!=expected[i] || data[33+i*2]) return {};
    if(data[52]>1) return {}; return data[52]!=0;
}
inline std::vector<std::uint8_t> firmware(const wchar_t* name) {
    std::vector<std::uint8_t> data(65536);
    DWORD n=GetFirmwareEnvironmentVariableW(name,L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}",data.data(),static_cast<DWORD>(data.size()));
    data.resize(n);return data;
}
template<class Events> inline void efi_context(const Events& events,bool tbs_available) {
    if(!enabled("efi")) return;
    auto f=observation("ECHO.EFI.BOOT_CONTEXT","efi","measured_boot","current_boot",0,"firmware",
        "OEM firmware, multiboot, recovery media, updates and policy changes; unknown is not disabled.");
    const auto sb=firmware(L"SecureBoot"),current=firmware(L"BootCurrent"),order=firmware(L"BootOrder");
    std::optional<bool> declared;
    if(sb.size()==1 && sb[0]<=1) declared=sb[0]!=0;
    f.evidence.push_back(declared?(*declared?"firmware_secure_boot=enabled":"firmware_secure_boot=disabled"):"firmware_secure_boot=unavailable");
    f.evidence.push_back(tbs_available?"tbs_log=available":"tbs_log=unavailable");
    if(current.size()==2) {
        unsigned id=current[0]|(current[1]<<8); bool listed=false;
        for(std::size_t i=0;i+1<order.size();i+=2) if((order[i]|(order[i+1]<<8))==id) listed=true;
        f.evidence.push_back("boot_current="+std::to_string(id));
        f.evidence.push_back(order.empty() || order.size()%2?"boot_order=unavailable_or_malformed":listed?"boot_current_in_order":"boot_current_not_in_order");
        wchar_t boot[16]{}; swprintf_s(boot,L"Boot%04X",id); auto entry=firmware(boot);
        f.evidence.push_back(entry.size()>=6?"boot_entry=present":"boot_entry=unavailable");
    } else f.evidence.push_back("boot_current=unavailable");
    std::optional<bool> measured; bool conflict=false;
    for(const auto& e:events) {
        if(e.pcr!=7 || e.type!=0x80000001u) continue; // EV_EFI_VARIABLE_DRIVER_CONFIG
        auto value=measured_secure_boot(e.data);
        if(value){if(measured && *measured!=*value) conflict=true;measured=value;}
    }
    if(measured && !conflict) {
        f.sources.insert("tpm_measured_boot"); f.evidence.push_back(*measured?"measured_secure_boot=enabled":"measured_secure_boot=disabled");
        if(declared && *declared!=*measured){f.id="ECHO.EFI.SECURE_BOOT_MISMATCH";f.severity=Severity::low;f.confidence=Confidence::medium;}
    } else f.evidence.push_back(conflict?"measured_secure_boot=conflicting_events":"measured_secure_boot=unavailable");
    submit(std::move(f));
}
} // namespace echo_integration
