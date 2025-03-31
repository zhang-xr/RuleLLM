rule Suspicious_IP_URL {
    meta:
        author = "RuleLLM"
        description = "Detects the use of a suspicious IP address in a URL."
        confidence = "85"
        severity = "80"

    strings:
        $suspicious_ip = "http://124.70.159.15:60006/"

    condition:
        $suspicious_ip
}