rule Suspicious_SystemInfo_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious system information exfiltration patterns"
        confidence = 85
        severity = 75
    strings:
        $system_info_vars = /(publicIP|hostname|homeDirectory|currentDirectory|currentTime)\s*=/ ascii wide
        $urlopen_call = "urlopen(" ascii wide
        $ip_address = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
        $port_number = /:\d{1,5}/ ascii wide
    condition:
        all of ($system_info_vars, $urlopen_call) and
        any of ($ip_address, $port_number) and
        #system_info_vars >= 3
}