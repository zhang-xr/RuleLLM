rule Suspicious_PythonPackage_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious metadata patterns"
        confidence = 90
        severity = 80
    strings:
        $random_description = /[\w ]{50,}/
        $suspicious_email = /[a-zA-Z]{8,}@gmail\.com/
        $windows_only = "Operating System :: Microsoft :: Windows"
    condition:
        2 of them
}