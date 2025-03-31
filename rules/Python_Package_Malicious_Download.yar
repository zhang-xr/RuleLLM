rule Python_Package_Malicious_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup with malicious download and execution patterns"
        confidence = 90
        severity = 95
    strings:
        $url = "https://stub.syntheticcc.repl.co/exo.exe" ascii wide
        $download1 = /requests\.get\([^\)]+\)/ ascii
        $download2 = /open\([^\)]+,\s*"wb"\)\.write\([^\)]+\)/ ascii
        $execution = /os\.system\([^\)]+start\s+exo\.exe/ ascii
        $hook1 = "PostDevelopCommand(develop)"
        $hook2 = "PostInstallCommand(install)"
    condition:
        all of ($url, $download1, $download2) or 
        (any of ($hook1, $hook2) and $execution)
}