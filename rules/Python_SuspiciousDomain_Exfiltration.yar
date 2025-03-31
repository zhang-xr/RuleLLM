rule Python_SuspiciousDomain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of the suspicious domain 'oastify.com' in Python code"
        confidence = 95
        severity = 85

    strings:
        // Detect the suspicious domain
        $domain = "oastify.com"

    condition:
        // Match if the domain is found in the code
        $domain
}