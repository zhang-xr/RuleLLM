rule Python_TempFile_RemoteCodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code creating temp files for remote code execution"
        confidence = 90
        severity = 85
        reference = "Analyzed code segment"
    
    strings:
        $tempfile_write = /_?ttmp\.write\(b?["']from urllib\.request import urlopen/
        $exec_pattern = /exec\(_?u?urlopen\(['"].+['"]\)\.read\(\)\)/
        $system_call = /_?ssystem\(f?["']start ["']?{_?eexecutable\.replace\(['"]\.exe['"], ['"]w\.exe['"]\)}/
        $tempfile_close = "_ttmp.close()"
    
    condition:
        all of ($tempfile_write, $exec_pattern, $system_call, $tempfile_close)
}