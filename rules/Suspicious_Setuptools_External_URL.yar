rule Suspicious_Setuptools_External_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of setuptools with external URLs"
        confidence = 85
        severity = 75
    strings:
        $setuptools = "setuptools"
        $webhook_url = /https?:\/\/[^\s"]+/ 
        $urlopen = "urllib.request.urlopen"
    condition:
        $setuptools and $webhook_url and $urlopen
}