#pragma once
#include "core.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#include <wintrust.h>
#include <softpub.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#pragma comment(lib,"wevtapi.lib")
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib,"advapi32.lib")

namespace echo_integration {
inline std::string utf8(const std::wstring& w) {
    if(w.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    std::string s(n,'\0'); if(n) WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),s.data(),n,nullptr,nullptr); return s;
}
inline std::int64_t epoch(std::uint64_t ft) { return ft>=116444736000000000ULL ? static_cast<std::int64_t>((ft-116444736000000000ULL)/10000000) : 0; }
inline std::int64_t file_epoch(FILETIME ft) { return epoch((std::uint64_t(ft.dwHighDateTime)<<32)|ft.dwLowDateTime); }
inline std::wstring env(const wchar_t* name) {
    DWORD n=GetEnvironmentVariableW(name,nullptr,0); if(!n || n>32768) return {};
    std::wstring s(n,L'\0'); DWORD got=GetEnvironmentVariableW(name,s.data(),n);
    if(!got || got>=n) return {}; s.resize(got); return s;
}
struct EventHandle {
    EVT_HANDLE value=nullptr;
    explicit EventHandle(EVT_HANDLE h=nullptr):value(h){}
    ~EventHandle(){if(value) EvtClose(value);}
    EventHandle(const EventHandle&)=delete; EventHandle& operator=(const EventHandle&)=delete;
};
struct Event {
    unsigned id=0, pid=0; std::uint64_t record=0; std::int64_t timestamp=0;
    std::wstring provider; std::vector<std::wstring> data;
};
inline std::vector<unsigned long long> render_values(EVT_HANDLE context,EVT_HANDLE event,DWORD& count) {
    DWORD used=0; count=0;
    EvtRender(context,event,EvtRenderEventValues,0,nullptr,&used,&count);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER || used>1024*1024) return {};
    std::vector<unsigned long long> buf((used+7)/8);
    if(!EvtRender(context,event,EvtRenderEventValues,static_cast<DWORD>(buf.size()*8),buf.data(),&used,&count)) return {};
    return buf;
}
struct EventReadResult { DWORD error=ERROR_SUCCESS; std::size_t count=0; bool limited=false; };
template<class F> inline EventReadResult read_events(const wchar_t* channel,const std::wstring& filter,F callback) {
    EventReadResult result; Budget budget;
    EventHandle query(EvtQuery(nullptr,channel,filter.c_str(),EvtQueryChannelPath|EvtQueryReverseDirection));
    if(!query.value){result.error=GetLastError();return result;}
    EventHandle sys(EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem));
    EventHandle user(EvtCreateRenderContext(0,nullptr,EvtRenderContextUser));
    if(!sys.value || !user.value){result.error=GetLastError();return result;}
    while(budget.take()) {
        EVT_HANDLE raw=nullptr; DWORD returned=0;
        if(!EvtNext(query.value,1,&raw,100,0,&returned)) {
            result.error=GetLastError(); if(result.error==ERROR_NO_MORE_ITEMS) result.error=ERROR_SUCCESS; return result;
        }
        EventHandle ev(raw); DWORD count=0;
        auto buf=render_values(sys.value,raw,count);
        if(buf.empty() || count<EvtSystemPropertyIdEND){result.error=ERROR_INVALID_DATA;continue;}
        auto* v=reinterpret_cast<EVT_VARIANT*>(buf.data()); Event e;
        e.id=v[EvtSystemEventID].UInt16Val; e.pid=v[EvtSystemProcessID].UInt32Val;
        e.record=v[EvtSystemEventRecordId].UInt64Val; e.timestamp=epoch(v[EvtSystemTimeCreated].FileTimeVal);
        if(v[EvtSystemProviderName].Type==EvtVarTypeString && v[EvtSystemProviderName].StringVal) e.provider=v[EvtSystemProviderName].StringVal;
        auto ub=render_values(user.value,raw,count);
        if(!ub.empty()) {
            auto* data=reinterpret_cast<EVT_VARIANT*>(ub.data());
            for(DWORD i=0;i<count;++i) if(data[i].Type==EvtVarTypeString && data[i].StringVal) e.data.emplace_back(data[i].StringVal);
        }
        ++result.count; callback(e);
    }
    result.limited=true; return result;
}
inline std::wstring recent_filter(const std::wstring& ids) {
    return L"*[System[("+ids+L") and TimeCreated[timediff(@SystemTime) <= "+std::to_wstring(policy.window_seconds*1000)+L"]]]";
}
inline void coverage(const char* category,const char* source,EventReadResult r) {
    if(!r.error && !r.limited) return;
    auto f=observation("ECHO.COVERAGE",category,"collection_status",source,0,source,"Unavailable or limited telemetry is not evidence of tampering.");
    f.evidence={"win32_error="+std::to_string(r.error),r.limited?"budget_exhausted":"source_unavailable"}; submit(std::move(f));
}
inline std::string context_field(const Event& e,const std::wstring& field) {
    for(const auto& d:e.data) {
        auto at=d.find(field+L"="); if(at==std::wstring::npos) at=d.find(field+L" =");
        if(at==std::wstring::npos) continue;
        at=d.find(L'=',at)+1; auto end=d.find_first_of(L"\r\n",at);
        auto value=d.substr(at,end==std::wstring::npos?end:end-at);
        const auto start=value.find_first_not_of(L" \t");
        if(start==std::wstring::npos) return {}; value.erase(0,start);
        value.erase(value.find_last_not_of(L" \t")+1); return utf8(value);
    }
    return {};
}
inline void powershell_context() {
    if(!enabled("powershell")) return;
    for(auto channel:{L"Windows PowerShell",L"PowerShellCore/Operational"}) {
        std::vector<Event> events;
        auto status=read_events(channel,recent_filter(L"EventID=400 or EventID=403"),[&](const Event& e){events.push_back(e);});
        coverage("powershell",utf8(channel).c_str(),status);
        std::reverse(events.begin(),events.end()); std::map<std::string,std::int64_t> starts;
        for(const auto& e:events) {
            std::string host=context_field(e,L"HostId"), runspace=context_field(e,L"RunspaceId");
            std::string session=host+":"+runspace;
            bool has_key=!host.empty();
            if(e.id==400){if(has_key) starts[session]=e.timestamp;continue;}
            auto f=observation("ECHO.POWERSHELL.SESSION_END","powershell","event_403",
                utf8(channel)+":"+std::to_string(e.record),e.timestamp,"evtx_powershell",
                "Normal session shutdown; absent start can be log rotation, retention, window boundary or provider differences.");
            f.evidence={channel==std::wstring(L"Windows PowerShell")?"edition=windows_powershell":"edition=powershell_core",
                "event_id=403","record="+std::to_string(e.record)};
            auto it=starts.find(session);
            if(has_key && it!=starts.end() && it->second<=e.timestamp){f.evidence.push_back("matched_start_400");f.evidence.push_back("duration_seconds="+std::to_string(e.timestamp-it->second));starts.erase(it);}
            else f.evidence.push_back("start_not_observed_in_window");
            submit(std::move(f));
        }
        EventHandle cfg(EvtOpenChannelConfig(nullptr,channel,0));
        if(cfg.value) {
            EVT_VARIANT val{}; DWORD used=0;
            if(EvtGetChannelConfigProperty(cfg.value,EvtChannelConfigEnabled,0,sizeof(val),&val,&used) && val.Type==EvtVarTypeBoolean && !val.BooleanVal) {
                auto f=observation("ECHO.POWERSHELL.LOG_DISABLED","powershell","channel_config",utf8(channel),0,"evtx_config","Logging can be disabled by normal administrative policy."); submit(std::move(f));
            }
        }
    }
    coverage("powershell","system_eventlog",read_events(L"System",recent_filter(L"EventID=104"),[](const Event& e){
        for(const auto& d:e.data) if(normalize(utf8(d)).find("powershell")!=std::string::npos){
            auto f=observation("ECHO.POWERSHELL.LOG_CLEARED","powershell","event_104",std::to_string(e.record),e.timestamp,"evtx_system","Administrative log maintenance; does not prove malicious clearing.");submit(std::move(f));break;
        }
    }));
}
// Verify embedded signatures without network access. No embedded signature is not
// equivalent to unsigned: catalog-only drivers must remain 'unknown'.
inline LONG embedded_signature(const std::wstring& path) {
    WINTRUST_FILE_INFO fi{}; fi.cbStruct=sizeof(fi); fi.pcwszFilePath=path.c_str();
    WINTRUST_DATA wd{}; wd.cbStruct=sizeof(wd); wd.dwUIChoice=WTD_UI_NONE;
    wd.fdwRevocationChecks=WTD_REVOKE_NONE; wd.dwUnionChoice=WTD_CHOICE_FILE; wd.pFile=&fi;
    wd.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL; wd.dwStateAction=WTD_STATEACTION_VERIFY;
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2; LONG result=WinVerifyTrust(nullptr,&action,&wd);
    wd.dwStateAction=WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr,&action,&wd); return result;
}
inline void defender_context() {
    if(!enabled("defender")) return;
    const auto pd=env(L"ProgramData"); if(pd.empty()) return;
    std::error_code ec; Budget budget; std::size_t files=0;
    for(const auto& entry:std::filesystem::directory_iterator(std::filesystem::path(pd)/L"Microsoft/Windows Defender/Support",ec)) {
        if(!budget.take() || files>=policy.max_files) break;
        const auto name=entry.path().filename().wstring();
        if(name.rfind(L"MPLog-",0)!=0 || entry.is_symlink(ec) || !entry.is_regular_file(ec)) continue;
        const auto size=entry.file_size(ec); if(ec || size>policy.max_file_bytes) continue; ++files;
        std::ifstream in(entry.path(),std::ios::binary); std::string bytes(static_cast<std::size_t>(size),'\0');
        if(!in.read(bytes.data(),static_cast<std::streamsize>(size))) continue;
        std::string text;
        if(bytes.size()>=2 && (unsigned char)bytes[0]==0xff && (unsigned char)bytes[1]==0xfe) {
            if(bytes.size()%2) continue; std::wstring w;
            for(std::size_t i=2;i+1<bytes.size();i+=2) w.push_back(static_cast<wchar_t>((unsigned char)bytes[i]|((unsigned char)bytes[i+1]<<8)));
            text=utf8(w);
        } else if(bytes.find('\0')==std::string::npos) text=std::move(bytes); else continue;
        std::istringstream lines(text); std::string line; std::size_t n=0;
        while(std::getline(lines,line) && budget.take()) {
            ++n; auto id=defender_indicator(line); if(id.empty()) continue;
            auto f=observation(id,"defender","defender_mplog",utf8(entry.path().wstring())+":"+std::to_string(n),0,"defender_log",
                "Undocumented Defender taint semantics vary by engine/build; diagnostic only.");
            f.evidence={"line="+std::to_string(n),"event_time=unverified","raw_text=discarded"}; submit(std::move(f));
        }
    }
}
} // namespace echo_integration
