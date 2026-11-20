#pragma once
// Native, local-only integration. No dependencies on the missing application PCH.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace echo_integration {
inline constexpr const char* version = "1.0.0-experimental";
enum class Severity { info, low, medium, high };
enum class Confidence { low, medium, high };
struct Policy {
    bool enabled = true;
    std::set<std::string> disabled;
    std::int64_t window_seconds = 5400;
    std::size_t max_records = 100000, max_findings = 2048, max_files = 128;
    std::size_t max_file_bytes = 32u << 20;
    int timeout_seconds = 15;
};
// Configure before start_scan; immutable while workers run.
inline Policy policy;
inline std::atomic<bool> cancelled{false};
inline bool enabled(const std::string& id) {
    return policy.enabled && !cancelled && !policy.disabled.count(id);
}
struct Budget {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::size_t records = 0;
    bool take() {
        return !cancelled && records++ < policy.max_records &&
            std::chrono::steady_clock::now() - start < std::chrono::seconds(policy.timeout_seconds);
    }
};
inline std::string normalize(std::string s) {
    for (auto& c : s) { if (c == '/') c = '\\'; if (c >= 'A' && c <= 'Z') c += 'a' - 'A'; }
    if (s.rfind("\\\\?\\", 0) == 0) s.erase(0, 4);
    return s;
}
inline bool ends(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size()-suffix.size(), suffix.size(), suffix) == 0;
}
inline std::string extension(const std::string& s) {
    auto dot = s.find_last_of('.'); auto slash = s.find_last_of("\\/");
    return dot == std::string::npos || (slash != std::string::npos && dot < slash) ? "" : normalize(s.substr(dot));
}
struct Finding {
    std::string id, category, artifact_type, source_path = "[local-only]";
    std::string entity; // Internal join key; never serialized (can contain a local path).
    std::int64_t timestamp = 0;
    Severity severity = Severity::info;
    Confidence confidence = Confidence::low;
    std::set<std::string> sources;
    std::vector<std::string> evidence;
    std::string false_positives;
    std::string rule_version = version;
};
inline std::mutex findings_mutex;
inline std::vector<Finding> findings;
inline void reset() { std::lock_guard<std::mutex> lock(findings_mutex); findings.clear(); cancelled = false; }
inline void submit(Finding f) {
    if (!enabled(f.category)) return;
    std::lock_guard<std::mutex> lock(findings_mutex);
    for (auto& old : findings) {
        if (old.id == f.id && old.entity == f.entity && old.timestamp == f.timestamp) {
            old.sources.insert(f.sources.begin(), f.sources.end());
            for (const auto& e : f.evidence)
                if (std::find(old.evidence.begin(), old.evidence.end(), e) == old.evidence.end()) old.evidence.push_back(e);
            return;
        }
    }
    if (findings.size() < policy.max_findings) findings.push_back(std::move(f));
}
inline std::vector<Finding> snapshot() { std::lock_guard<std::mutex> lock(findings_mutex); return findings; }
// Group only identical normalized entities in a bounded temporal window. Multiple
// rules from one source do not count as independent evidence. No severity escalation.
inline void correlate() {
    const auto rows=snapshot();
    for(const auto& seed:rows) {
        if(seed.entity.empty() || seed.timestamp<=0 || seed.id=="ECHO.CORRELATED") continue;
        Finding joined=seed; joined.id="ECHO.CORRELATED"; joined.category="correlation";
        joined.evidence={seed.id}; joined.severity=Severity::info;joined.confidence=Confidence::low;
        for(const auto& other:rows) {
            if(other.entity!=seed.entity || other.timestamp<=0 || other.id==seed.id ||
                other.id=="ECHO.CORRELATED" || other.timestamp<seed.timestamp || other.timestamp-seed.timestamp>300) continue;
            joined.sources.insert(other.sources.begin(),other.sources.end());joined.evidence.push_back(other.id);
        }
        if(joined.sources.size()>1) {joined.confidence=Confidence::medium;submit(std::move(joined));}
    }
}
inline Finding observation(std::string id, std::string category, std::string artifact,
                           std::string entity, std::int64_t ts, std::string source, std::string fp) {
    Finding f; f.id=std::move(id); f.category=std::move(category); f.artifact_type=std::move(artifact);
    f.entity=normalize(std::move(entity)); f.timestamp=ts; f.sources.insert(std::move(source)); f.false_positives=std::move(fp); return f;
}
inline std::vector<std::string> reasons(std::uint32_t r) {
    std::vector<std::string> out;
    for (const auto& p : std::vector<std::pair<std::uint32_t,const char*>>{
        {1,"data_overwrite"},{2,"data_extend"},{4,"data_truncation"},{0x100,"create"},
        {0x200,"delete"},{0x1000,"rename_old"},{0x2000,"rename_new"},
        {0x8000,"basic_info_change"},{0x80000000u,"close"}}) if (r & p.first) out.emplace_back(p.second);
    return out;
}
class UsnActivity {
    struct Activity { std::uint32_t reasons=0; std::string path; std::int64_t ts=0; };
    std::map<std::string,Activity> entries;
public:
    void add(const std::string& file_id, std::string path, std::int64_t ts, std::uint32_t reason, std::int64_t now) {
        if (!enabled("usn") || ts <= 0 || ts > now || now-ts > policy.window_seconds) return;
        path=normalize(std::move(path));
        // Aggregate only the same file reference and exact event second, not unrelated history.
        std::string key=file_id+":"+std::to_string(ts);
        if (!entries.count(key) && entries.size() >= policy.max_records) return;
        auto& a=entries[key]; a.reasons |= reason; a.path=path; a.ts=ts;
    }
    void finish() const {
        static const std::set<std::string> ext320={".exe",".odl",".pf",".log",".jrs",".xml",".jtx",".ldb",".dll",".tmp",".json",".node",".parc",".pak",".fsx",".java"};
        static const std::set<std::string> ext328={".odl",".pf",".jrs",".ldb",".dll",".json",".node",".parc",".pak",".fsx",".java"};
        for (const auto& item : entries) {
            const auto& a=item.second; const auto ext=extension(a.path);
            const bool r320=ext320.count(ext) && (a.reasons & 0x80008007u)==0x80008007u;
            const bool r328=ext328.count(ext) && (a.reasons & 7u)==7u;
            if (!r320 && !r328) continue;
            auto f=observation(r320?"ECHO.USN.320":"ECHO.USN.328","usn","usn_record",a.path,a.ts,"usn",
                "Updates, compaction, installers and normal file rewrites; no tampering verdict.");
            f.evidence=reasons(a.reasons); f.evidence.push_back("extension="+ext);
            f.evidence.push_back("file_reference="+item.first);
            submit(std::move(f));
        }
    }
};
struct DumpContext { bool valid=false;std::uint32_t timestamp=0;std::vector<std::uint8_t> process_path; };
inline DumpContext dump_context(const std::uint8_t* p,std::size_t size) {
    DumpContext out;
    auto u32=[&](std::size_t off){std::uint32_t n=0;if(off<=size && size-off>=4)std::memcpy(&n,p+off,4);return n;};
    if(!p || size<32 || u32(0)!=0x504d444d || (u32(4)&0xffff)!=0xa793) return out;
    const auto count=u32(8),dir=u32(12);
    if(count>4096 || dir>size || std::uint64_t(count)*12>size-dir) return out;
    out.valid=true;out.timestamp=u32(20);
    for(std::uint32_t i=0;i<count;++i) {
        const auto entry=std::size_t(dir)+i*12;
        if(u32(entry)!=4) continue; // ModuleListStream
        const auto length=u32(entry+4),rva=u32(entry+8);
        if(rva>size || length>size-rva || length<112 || u32(rva)==0) continue;
        const auto name=u32(std::size_t(rva)+24); // first MINIDUMP_MODULE.ModuleNameRva
        if(name>size || size-name<4) continue;const auto n=u32(name);
        if(n>32768 || n%2 || n>size-name-4) continue;
        out.process_path.assign(p+name+4,p+name+4+n);break;
    }
    return out;
}
inline void memory_context(const std::vector<std::uint8_t>& bytes, const std::string& entity,
                           std::int64_t ts, bool structural_pe) {
    if (!enabled("memory")) return;
    const std::string text(bytes.begin(),bytes.end());
    std::vector<std::string> found;
    // Provenance: Generic-Cheat-Injection.txt, supplied archive, 2026-11-20.
    // Generic developer/overlay symbols are context, never malicious IOCs.
    for (auto s : {"imgui_impl_dx11","imgui_impl_win32","imgui_impl_dx9","d3d11hook.cpp"})
        if (text.find(s)!=std::string::npos) found.emplace_back(s);
    if (found.empty()) return;
    auto f=observation("ECHO.MEMORY.OVERLAY_CONTEXT","memory","memory_region",entity,ts,"memory_strings",
        "Legitimate overlays, ImGui applications, development tools and debuggers.");
    f.evidence=std::move(found);
    f.evidence.push_back(structural_pe?"structural_pe_in_unbacked_executable_region":"unbacked_executable_region");
    // Same memory source is not independent corroboration, even with several strings.
    submit(std::move(f));
}
inline std::string defender_indicator(std::string line) {
    line=normalize(std::move(line));
    if (line.find("csrss.exe (")!=std::string::npos || line.find("\\driverstore\\")!=std::string::npos) return {};
    if (line.find("fivem_gtaprocess.exe")!=std::string::npos && line.find("is tainted: tainttype:0x2")!=std::string::npos) return "ECHO.DEFENDER.FIVEM_TAINT2";
    if (line.find("is tainted: tainttype:0x4")!=std::string::npos || line.find("originally tainted by: tainttype:0x4")!=std::string::npos) return "ECHO.DEFENDER.TAINT4";
    return {};
}
} // namespace echo_integration
