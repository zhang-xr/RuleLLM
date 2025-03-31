rule Malicious_Python_Hardcoded_IoCs {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded malicious IP and URL in setup.py"
        confidence = 100
        severity = 95

    strings:
        $ip_address = "34.136.130.116"
        $exfil_url = "http://gn7v017kvra8epx336tsoj42wt2kqce1.oastify.com"

    condition:
        $ip_address or $exfil_url
}