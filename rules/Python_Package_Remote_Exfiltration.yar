rule Python_Package_Remote_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages making remote requests with system information"
        confidence = 95
        severity = 85
    strings:
        $req1 = "import requests"
        $req2 = "requests.post(url, data=data)"
        $req3 = /https?:\/\/[^\s]+\.php/ nocase
        $req4 = /["']username["']\s*:/
    condition:
        all of ($req1, $req2) and any of ($req3, $req4)
}