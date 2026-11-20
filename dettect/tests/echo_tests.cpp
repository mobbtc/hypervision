#include "../detections/echo_integration/runtime.h"
#include "../detections/echo_integration/native_artifacts.h"
#include "../detections/echo_integration/efi_context.h"
#include <cassert>
#include <iostream>
#include <thread>

using namespace echo_integration;
int main() {
    policy=Policy{}; reset();
    assert(normalize("C:/Users/A/X.DLL")=="c:\\users\\a\\x.dll");
    assert(extension("c:/folder.dll/file").empty());
    UsnActivity u;u.add("C:1","x.dll",100,7,110);u.finish();
    assert(snapshot().size()==1 && snapshot()[0].id=="ECHO.USN.328");
    assert(snapshot()[0].severity==Severity::info);reset();
    UsnActivity full;full.add("C:1","x.exe",100,7,110);full.add("C:1","x.exe",100,0x80008000u,110);full.finish();
    assert(snapshot().size()==1 && snapshot()[0].id=="ECHO.USN.320");reset();
    UsnActivity negative;
    negative.add("C:1","x.dll",100,1,110);negative.add("D:1","x.dll",100,6,110);
    negative.add("C:2","x.dll",1,7,10000);negative.add("C:3","x.dll",111,7,110);
    negative.add("C:4","x.dll",100,0x80000000u,110);negative.finish();assert(snapshot().empty());
    policy.disabled.insert("usn");u.finish();assert(snapshot().empty());policy.disabled.clear();
    auto f=observation("test","memory","memory_region","C:/Users/private/secret",100,"memory","legitimate software");
    f.evidence={"symbol"};submit(f);submit(f);assert(snapshot().size()==1);
    auto json=results_json();assert(json.find("secret")==std::string::npos);assert(json.find("private")==std::string::npos);
    assert(json_string("a\"\n\\")=="\"a\\\"\\u000a\\\\\"");reset();
    std::vector<std::uint8_t> text{'h','e','l','l','o'};memory_context(text,"pid:1:region:1",100,false);assert(snapshot().empty());
    std::string overlay="imgui_impl_dx11 imgui_impl_win32";text.assign(overlay.begin(),overlay.end());
    memory_context(text,"pid:1:region:1",100,true);assert(snapshot().size()==1);assert(snapshot()[0].severity==Severity::info);reset();
    assert(defender_indicator("FiveM_GTAProcess.exe is tainted: TaintType:0x2")=="ECHO.DEFENDER.FIVEM_TAINT2");
    assert(defender_indicator("FiveM_GTAProcess.exe is tainted: TaintType:0x2 csrss.exe (").empty());
    assert(defender_indicator("normal FiveM_GTAProcess.exe startup").empty());
    assert(shortcut_context_match("C:/Windows/System32/cmd.exe","/c start Discord"));
    assert(!shortcut_context_match("C:/Users/a/Discord.exe",""));
    assert(!shortcut_context_match("C:/Windows/System32/cmd.exe","/c echo hello"));
    Event event;event.data={L"HostId = abc\r\nRunspaceId=def\r\nHostApplication=secret"};
    assert(context_field(event,L"HostId")=="abc");assert(context_field(event,L"RunspaceId")=="def");
    assert(context_field(event,L"Missing").empty());
    std::vector<std::uint8_t> measured(53,0);
    const std::uint8_t guid[]={0x61,0xdf,0xe4,0x8b,0xca,0x93,0xd2,0x11,0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c};
    std::copy(std::begin(guid),std::end(guid),measured.begin());measured[16]=10;measured[24]=1;
    const std::string name="SecureBoot";for(std::size_t i=0;i<name.size();++i)measured[32+2*i]=name[i];measured[52]=1;
    assert(measured_secure_boot(measured).value());measured[52]=0;assert(!measured_secure_boot(measured).value());
    measured[0]=0;assert(!measured_secure_boot(measured));
    for(std::size_t n=0;n<53;++n)assert(!measured_secure_boot(std::vector<std::uint8_t>(n)));
    std::vector<std::uint8_t> dump(32,0);
    auto put=[&](std::size_t at,std::uint32_t value){std::memcpy(dump.data()+at,&value,4);};
    put(0,0x504d444d);put(4,0xa793);put(20,12345);
    assert(dump_context(dump.data(),dump.size()).valid);
    assert(dump_context(dump.data(),dump.size()).timestamp==12345);
    put(8,0xffffffffu);assert(!dump_context(dump.data(),dump.size()).valid);
    for(std::size_t n=0;n<32;++n)assert(!dump_context(dump.data(),n).valid);
    reset();auto a=observation("one","test","file","C:/x.dll",100,"usn","update");
    auto b=observation("two","test","file","c:\\x.dll",101,"yara","overlay");
    submit(a);submit(b);correlate();assert(snapshot().size()==3);assert(snapshot().back().severity==Severity::info);
    reset();b.sources={"usn"};submit(a);submit(b);correlate();assert(snapshot().size()==2);reset();
    policy.max_findings=4;
    std::vector<std::thread> threads;
    for(int i=0;i<8;++i)threads.emplace_back([i]{for(int j=0;j<100;++j)submit(observation("t","test","fixture",std::to_string(i),j,"test","fixture"));});
    for(auto& t:threads)t.join();assert(snapshot().size()==4);reset();policy=Policy{};
    Module module;module.id="throws";module.run=[]{throw 42;};run_module(module);
    assert(metrics.back().failed);
    cancelled=true;Budget budget;assert(!budget.take());reset();
    std::cout<<"PASS: native headers compile; USN, minimization, memory, Defender, LNK, event context, UEFI bounds, concurrency and cancellation fixtures\n";
}
