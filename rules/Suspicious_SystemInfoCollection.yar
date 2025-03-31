rule Suspicious_SystemInfoCollection {
    meta:
        author = "RuleLLM"
        description = "Detects collection of system information for potential malicious purposes"
        confidence = "85"
        severity = "75"
    
    strings:
        $system_info = /platform\.(node|uname)\(\)/
        $network_info = /os\.popen\(\"ifconfig\|grep inet\|grep -v inet6\"\)/
        $base64_encode = "base64.b64encode"
    
    condition:
        all of them
}