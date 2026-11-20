#pragma once
namespace echo_integration {
inline constexpr const char* yara_source=R"ECHOYARA(
// Provenance: supplied Echo Jean rules, reviewed 2026-11-20. Review due 2027-02-20.
// Context only. None of these rules establishes malicious execution.
rule ECHO_DUMP_GRAPHICS_CONTEXT {
    meta:
        version = "1.0.0"
        source = "CrashDumps-T-M.txt:hellomoto"
        false_positives = "Games, graphics programs and overlays"
    strings:
        $a = "xinput1_4.dll" wide ascii nocase
        $b = "d3dcompiler_43.dll" wide ascii nocase
        $c = "dxgi.dll" wide ascii nocase
        $d = "dxcore.dll" wide ascii nocase
    condition:
        uint32(0) == 0x504d444d and all of them
}
rule ECHO_DUMP_PYMEOW_CONTEXT {
    meta:
        version = "1.0.0"
        source = "CrashDumps-T-M.txt:ginn"
        false_positives = "Legitimate Python automation and overlays; stale dump content"
    strings:
        $a = "d3d11.dll" wide ascii nocase
        $b = "xinput1_4.dll" wide ascii nocase
        $c = "pyMeow.pyd" wide ascii nocase
        $d = "dxcore.dll" wide ascii nocase
    condition:
        uint32(0) == 0x504d444d and all of them
}
rule ECHO_JAVA_DOWNLOAD_CONTEXT {
    meta:
        version = "1.0.0"
        source = "java-dropper-iqvw64e.txt"
        false_positives = "Source code, tutorials, legitimate download clients; not execution"
    strings:
        $a = "import java.util." ascii
        $b = "url.openStream().readAllBytes()" ascii
        $c = "URL url = URI.create(" ascii
    condition:
        filesize < 32MB and $a and ($b or $c)
}
rule ECHO_DRIVER_IQVW64E_REFERENCE {
    meta:
        version = "1.0.0"
        source = "java-dropper-iqvw64e.txt"
        false_positives = "Legitimate Intel driver packages and security research; reference is not use"
    strings:
        $a = "Nal Windows Driver Unload: Starting" ascii
        $b = "iqvw64e.pdb" ascii
        $c = "MmUnmapIoSpace" ascii
    condition:
        filesize < 32MB and all of them
}
)ECHOYARA";
}
