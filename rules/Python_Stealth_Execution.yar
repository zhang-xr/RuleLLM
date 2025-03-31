rule Python_Stealth_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects stealthy execution patterns in Python code"
        confidence = 95
        severity = 85
    strings:
        $s1 = "set __COMPACT_LAYER=RunAsInvoker | start" ascii wide
        $s2 = "open(\"Cleaner.exe\", \"wb\").write(response.content)" ascii wide
        $s3 = "os.system(" ascii wide
        $s4 = "requests.get(" ascii wide
    condition:
        all of ($s1, $s2) or all of ($s3, $s4)
}