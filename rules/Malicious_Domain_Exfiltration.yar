rule Malicious_Domain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of a hardcoded malicious domain used for data exfiltration."
        confidence = 95
        severity = 85

    strings:
        $malicious_domain = "csngft88cumgfr3deiig43by9rko6sn7o.oast.fun" ascii

    condition:
        $malicious_domain
}