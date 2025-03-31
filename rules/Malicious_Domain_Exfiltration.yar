rule Malicious_Domain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP POST requests to a known malicious domain used for data exfiltration."
        confidence = "95"
        severity = "90"

    strings:
        $malicious_domain = "http://csngft88cumgfr3deiig43by9rko6sn7o.oast.fun"

    condition:
        $malicious_domain
}