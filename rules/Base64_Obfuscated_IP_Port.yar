rule Base64_Obfuscated_IP_Port {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded IP addresses and ports commonly used in malicious scripts"
        confidence = 85
        severity = 80

    strings:
        $base64_ip = /[A-Za-z0-9+\/]{10,}={0,2}/ nocase
        $base64_port = /[A-Za-z0-9+\/]{2,6}={0,2}/ nocase

    condition:
        any of ($base64_ip, $base64_port) and
        #base64_ip > 1 and
        #base64_port > 0
}