rule Suspicious_Webhost_Domain {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious webhost domains commonly used in malware"
        confidence = 90
        severity = 85
        
    strings:
        $webhost_domain = /([a-z0-9]+\.)?000webhostapp\.com/ nocase
        $download_pattern = /Invoke-WebRequest.*https?:\/\/[^\s]+000webhostapp\.com/ nocase
        
    condition:
        $webhost_domain and $download_pattern
}