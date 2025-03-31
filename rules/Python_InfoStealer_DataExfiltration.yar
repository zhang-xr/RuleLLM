rule Python_InfoStealer_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code exfiltrating data via HTTP requests"
        confidence = 95
        severity = 90
    strings:
        $s1 = /base64\.b64encode\(.*\)/
        $s2 = /urllib\.request\.Request\(/
        $s3 = /urlopen\(.*timeout=.*\)/
        $s4 = /http:\/\/[\d\.]+:\d+\/\?token=/
        $s5 = /request\(url=.*encode\)/
    condition:
        3 of ($s*) and any of ($s4, $s5)
}