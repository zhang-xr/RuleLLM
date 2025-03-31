rule Python_UAC_Bypass_CompactLayer {
    meta:
        author = "RuleLLM"
        description = "Detects UAC bypass attempt using __COMPACT_LAYER in Python code"
        confidence = 95
        severity = 90
    strings:
        $compact_layer = "__COMPACT_LAYER=RunAsInvoker" ascii wide
        $start_exe = /start\s+\w+\.exe/ ascii wide
        $os_system = "os.system" ascii wide
    condition:
        all of them and 
        filesize < 10KB
}