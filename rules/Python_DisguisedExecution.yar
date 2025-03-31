rule Python_DisguisedExecution {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to disguise Python execution using pythonw.exe"
        confidence = 85
        severity = 80
        reference = "Analyzed code segment"
    
    strings:
        $executable_replace = /_?eexecutable\.replace\(['"]\.exe['"], ['"]w\.exe['"]\)/
        $system_call = /_?ssystem\(f?["']start ["']?.+\.exe/
    
    condition:
        $executable_replace and $system_call
}