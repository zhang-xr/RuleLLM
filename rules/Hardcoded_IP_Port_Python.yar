rule Hardcoded_IP_Port_Python {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded suspicious IP and port in Python code"
        confidence = 85
        severity = 80

    strings:
        $ip = "85.159.212.47"
        $port = "61985"

    condition:
        $ip and $port
}