rule Data_Exfiltration_Base64_FQDN {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoding of FQDN and exfiltration via URL"
        confidence = 95
        severity = 90
    strings:
        $base64_encode = "base64.b64encode"
        $socket_fqdn = "socket.getfqdn()"
        $url = /https?:\/\/[^\s]+\?/
    condition:
        all of them
}