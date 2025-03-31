rule Python_Stealth_Execution_Patterns {
    meta:
        author = "RuleLLM"
        description = "Detects stealthy execution patterns in Python code"
        confidence = 85
        severity = 85
    strings:
        $compact_layer = "__COMPACT_LAYER=RunAsInvoker" ascii wide
        $pipe_exec = "| start" ascii wide
        $getpass = "getpass.getuser()" ascii wide
        $time_stamp = "int(time.time())" ascii wide
    condition:
        3 of them and 
        filesize < 10KB
}