rule Suspicious_Process_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious process execution patterns with COMPACT_LAYER manipulation"
        confidence = 85
        severity = 80
    
    strings:
        $compact_layer = "__COMPACT_LAYER=RunAsInvoker"
        $start_cmd = "start"
        $file_exe = "FILE.exe"
    
    condition:
        $compact_layer and
        $start_cmd and
        $file_exe
}