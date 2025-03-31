rule Malicious_Python_Package_Payload_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python package that downloads and executes a malicious payload from a remote URL"
        confidence = 95
        severity = 90

    strings:
        $url_fetch = /urllib\.request\.urlopen\s*\(\s*["']https:\/\/[^"']+["']\s*\)/
        $payload_save = /with\s+open\s*\(\s*[^,]+\s*,\s*["']wb["']\s*\)\s+as\s+[^:]+:/
        $subprocess_exec = /subprocess\.run\s*\(\s*\["start"\s*,\s*[^]]+\]\s*,\s*shell\s*=\s*True\s*\)/

    condition:
        all of them
}