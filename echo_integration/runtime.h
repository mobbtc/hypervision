#pragma once
#include "windows_support.h"
#include <functional>

namespace echo_integration {
struct Module {
    std::string id, category, version="legacy", permissions="unknown", sources="legacy", cost="unmeasured";
    std::function<void()> run;
};
struct Metric { std::string id; long long milliseconds=0; bool failed=false; };
inline std::mutex metrics_mutex;
inline std::vector<Metric> metrics;
inline std::vector<Module> inventory;
inline void run_module(const Module& m) {
    const auto start=std::chrono::steady_clock::now(); bool failed=false;
    try { m.run(); } catch(...) { failed=true; }
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
    std::lock_guard<std::mutex> lock(metrics_mutex); metrics.push_back({m.id,ms,failed});
}
inline std::string json_string(const std::string& s) {
    std::string out="\""; const char* hex="0123456789abcdef";
    for(unsigned char c:s) {
        if(c=='"' || c=='\\'){out+='\\';out+=static_cast<char>(c);}
        else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
        else out+=static_cast<char>(c);
    }
    return out+'"';
}
template<class T> inline std::string json_array(const T& values) {
    std::string out="["; bool first=true;
    for(const auto& v:values){if(!first)out+=',';first=false;out+=json_string(v);}return out+"]";
}
inline std::string results_json() {
    const auto rows=snapshot(); std::map<std::string,std::size_t> entities;
    std::string out="{\"schema_version\":1,\"rule_version\":"+json_string(version)+",\"upload_enabled\":false,\"findings\":[";
    bool first=true;
    for(const auto& f:rows) {
        if(!first)out+=',';first=false;
        if(!entities.count(f.entity)) entities[f.entity]=entities.size()+1;
        out+="{\"id\":"+json_string(f.id)+",\"category\":"+json_string(f.category)+",\"confidence\":"+json_string(f.confidence==Confidence::high?"high":f.confidence==Confidence::medium?"medium":"low")+
            ",\"severity\":"+json_string(f.severity==Severity::high?"high":f.severity==Severity::medium?"medium":f.severity==Severity::low?"low":"info")+
            ",\"artifact_type\":"+json_string(f.artifact_type)+",\"source_path\":\"[local-only]\",\"entity_id\":"+std::to_string(entities[f.entity])+
            ",\"timestamp\":"+std::to_string(f.timestamp)+",\"evidence\":"+json_array(f.evidence)+",\"sources\":"+json_array(f.sources)+
            ",\"rule_version\":"+json_string(f.rule_version)+",\"false_positives\":"+json_string(f.false_positives)+"}";
    }
    out+="],\"modules\":[";first=true;
    for(const auto& m:inventory) {
        if(!first)out+=',';first=false;
        out+="{\"id\":"+json_string(m.id)+",\"category\":"+json_string(m.category)+",\"version\":"+json_string(m.version)+
            ",\"permissions\":"+json_string(m.permissions)+",\"sources\":"+json_string(m.sources)+",\"cost\":"+json_string(m.cost)+"}";
    }
    out+="],\"metrics\":[";first=true;std::lock_guard<std::mutex> lock(metrics_mutex);
    for(const auto& m:metrics){if(!first)out+=',';first=false;out+="{\"id\":"+json_string(m.id)+",\"milliseconds\":"+std::to_string(m.milliseconds)+",\"failed\":"+(m.failed?"true":"false")+"}";}
    return out+"]}";
}
inline bool write_local_results() {
    const auto local=env(L"LOCALAPPDATA"); if(local.empty()) return false;
    const auto dir=std::filesystem::path(local)/L"dettect"/L"echo-integration";
    std::error_code ec;std::filesystem::create_directories(dir,ec);if(ec)return false;
    std::ofstream out(dir/L"latest.json",std::ios::binary|std::ios::trunc);
    out<<results_json();out.flush();return out.good();
}
} // namespace echo_integration
