#pragma once
#include "windows_support.h"
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"shell32.lib")

namespace echo_integration {
inline std::wstring driver_path(std::wstring value) {
    if(value.size()>1 && value.front()==L'"' && value.back()==L'"') value=value.substr(1,value.size()-2);
    if(value.rfind(L"\\??\\",0)==0) value.erase(0,4);
    wchar_t windows[MAX_PATH]{}; GetWindowsDirectoryW(windows,MAX_PATH);
    if(value.rfind(L"\\SystemRoot\\",0)==0) value=std::wstring(windows)+value.substr(11);
    else if(value.rfind(L"System32\\",0)==0) value=std::wstring(windows)+L"\\"+value;
    wchar_t expanded[32768]{};
    DWORD n=ExpandEnvironmentStringsW(value.c_str(),expanded,32768);
    return n && n<=32768 ? expanded : value;
}
inline bool user_path_hint(const std::string& path) {
    const auto p=normalize(path);
    // A location hint, not an ACL/writability determination.
    return p.find("\\users\\")!=std::string::npos || p.find("\\temp\\")!=std::string::npos;
}
inline void driver_context() {
    if(!enabled("drivers")) return;
    std::set<std::string> running_drivers;
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE);
    if(manager) {
        DWORD needed=0,count=0,resume=0;
        EnumServicesStatusExW(manager,SC_ENUM_PROCESS_INFO,SERVICE_DRIVER,SERVICE_ACTIVE,nullptr,0,&needed,&count,&resume,nullptr);
        if(GetLastError()==ERROR_MORE_DATA && needed<=4u*1024*1024) {
            std::vector<unsigned long long> data((needed+7)/8);resume=0;
            if(EnumServicesStatusExW(manager,SC_ENUM_PROCESS_INFO,SERVICE_DRIVER,SERVICE_ACTIVE,
                reinterpret_cast<LPBYTE>(data.data()),static_cast<DWORD>(data.size()*8),&needed,&count,&resume,nullptr)) {
                auto* services=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(data.data()); Budget budget;
                for(DWORD i=0;i<count && budget.take();++i) {
                    if(services[i].ServiceStatusProcess.dwCurrentState!=SERVICE_RUNNING) continue;
                    SC_HANDLE service=OpenServiceW(manager,services[i].lpServiceName,SERVICE_QUERY_CONFIG);
                    if(!service) continue; DWORD bytes=0;
                    QueryServiceConfigW(service,nullptr,0,&bytes);
                    if(GetLastError()==ERROR_INSUFFICIENT_BUFFER && bytes<=65536) {
                        std::vector<unsigned long long> config((bytes+7)/8);
                        auto* c=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
                        if(QueryServiceConfigW(service,c,static_cast<DWORD>(config.size()*8),&bytes) && c->lpBinaryPathName)
                            running_drivers.insert(normalize(utf8(driver_path(c->lpBinaryPathName))));
                    }
                    CloseServiceHandle(service);
                }
            }
        }
        CloseServiceHandle(manager);
    }
    struct CiEvent {std::string path;std::int64_t ts;}; std::vector<CiEvent> ci;
    coverage("drivers","code_integrity",read_events(L"Microsoft-Windows-CodeIntegrity/Operational",
        recent_filter(L"EventID=3077 or EventID=3033"),[&](const Event& e){
            for(const auto& d:e.data) if(ends(normalize(utf8(d)),".sys")) ci.push_back({normalize(utf8(driver_path(d))),e.timestamp});
        }));
    coverage("drivers","service_install",read_events(L"System",recent_filter(L"EventID=7045"),[&](const Event& e){
        if(e.provider!=L"Service Control Manager") return;
        for(const auto& d:e.data) {
            auto path=driver_path(d); auto key=normalize(utf8(path)); if(!ends(key,".sys")) continue;
            auto f=observation("ECHO.DRIVER.RECENT_INSTALL","drivers","driver_service",key,e.timestamp,"service_install",
                "Legitimate driver installation/update; catalog-only signature status is unknown.");
            f.evidence={"event_id=7045",user_path_hint(key)?"user_location_hint":"non_user_location"};
            f.evidence.push_back(running_drivers.count(key)?"service_state=running":"service_running_state=not_observed");
            LONG trust=embedded_signature(path);
            f.evidence.push_back(trust==ERROR_SUCCESS?"embedded_signature=valid":trust==TRUST_E_BAD_DIGEST?"embedded_signature=bad_digest":"signature=unknown_or_untrusted");
            for(const auto& c:ci) if(c.path==key && std::llabs(c.ts-e.timestamp)<=300) {
                f.sources.insert("code_integrity"); f.evidence.push_back("code_integrity_enforcement_within_300s");
                f.confidence=Confidence::medium; f.severity=Severity::low; break;
            }
            submit(std::move(f)); break;
        }
    }));
}
inline bool shortcut_context_match(const std::string& target,const std::string& args) {
    if(!ends(normalize(target),"\\cmd.exe")) return false;
    auto a=normalize(args);
    return a.find("discord")!=std::string::npos || a.find("fivem")!=std::string::npos ||
           a.find("spotify")!=std::string::npos || a.find("obs64")!=std::string::npos;
}
inline void shortcut_context() {
    if(!enabled("lnk")) return;
    HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(init) && init!=RPC_E_CHANGED_MODE) return;
    struct Cleanup {bool uninit;~Cleanup(){if(uninit)CoUninitialize();}} cleanup{SUCCEEDED(init)};
    std::vector<std::filesystem::path> roots;
    for(const KNOWNFOLDERID* id:{&FOLDERID_Desktop,&FOLDERID_StartMenu,&FOLDERID_CommonStartMenu,&FOLDERID_Recent}) {
        PWSTR p=nullptr; if(SUCCEEDED(SHGetKnownFolderPath(*id,KF_FLAG_DONT_VERIFY,nullptr,&p))){roots.emplace_back(p);CoTaskMemFree(p);}
    }
    Budget budget; std::size_t count=0;
    for(const auto& root:roots) {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,ec),end;
        for(;it!=end;it.increment(ec)) {
            if(ec) {ec.clear();continue;} if(!budget.take() || count>=policy.max_files) return;
            DWORD attrs=GetFileAttributesW(it->path().c_str());
            if(attrs==INVALID_FILE_ATTRIBUTES) continue;
            if(attrs&FILE_ATTRIBUTE_REPARSE_POINT){it.disable_recursion_pending();continue;}
            if(it.depth()>6) {it.disable_recursion_pending();continue;}
            if(!it->is_regular_file(ec) || extension(utf8(it->path().wstring()))!=".lnk") continue;
            auto size=it->file_size(ec); if(ec || size>500000) continue; ++count;
            Microsoft::WRL::ComPtr<IShellLinkW> link;
            if(FAILED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(link.GetAddressOf())))) continue;
            Microsoft::WRL::ComPtr<IPersistFile> persist; if(FAILED(link.As(&persist))) continue;
            if(FAILED(persist->Load(it->path().c_str(),STGM_READ))) continue;
            wchar_t target[32768]{},args[32768]{};
            // Never Resolve or execute a shortcut; read its stored target/arguments.
            if(FAILED(link->GetPath(target,32768,nullptr,SLGP_RAWPATH)) || FAILED(link->GetArguments(args,32768))) continue;
            if(!shortcut_context_match(utf8(target),utf8(args))) continue;
            WIN32_FILE_ATTRIBUTE_DATA fa{}; GetFileAttributesExW(it->path().c_str(),GetFileExInfoStandard,&fa);
            auto f=observation("ECHO.LNK.SHELL_APP_CONTEXT","lnk","shell_link",utf8(it->path().wstring()),file_epoch(fa.ftLastWriteTime),"shell_link",
                "Normal launch wrappers and streaming shortcuts; no execution inferred from shortcut presence.");
            auto a=normalize(utf8(args));
            f.evidence={"stored_target=cmd.exe",user_path_hint(utf8(target))?"target_user_location_hint":"target_non_user_location",
                a.find("&&")!=std::string::npos || a.find('|')!=std::string::npos?"command_chaining_present":"command_chaining_absent",
                embedded_signature(target)==ERROR_SUCCESS?"target_embedded_signature=valid":"target_signature=unknown_or_untrusted",
                "timestamp=shortcut_last_write","arguments=discarded"}; submit(std::move(f));
        }
    }
}
} // namespace echo_integration
