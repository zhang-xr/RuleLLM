rule Python_InfoStealer_SystemInfoCollection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information for exfiltration"
        confidence = 90
        severity = 80
    strings:
        $s1 = /os\.getlogin\(\)/
        $s2 = /platform\.node\(\)/
        $s3 = /platform\.platform\(\)/
        $s4 = /socket\.socket\(.*\)/
        $s5 = /getsockname\(\[0\]\)/
        $s6 = /os\.popen\(.*\/flag.*\)/
    condition:
        3 of ($s*) and any of ($s6)
}