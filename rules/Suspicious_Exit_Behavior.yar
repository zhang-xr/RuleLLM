rule Suspicious_Exit_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of exit(0) to hide malicious activity"
        confidence = 80
        severity = 75

    strings:
        $exit_0 = "exit(0)" ascii
        $requests_import = "import requests" ascii
        $subprocess_import = "import subprocess" ascii

    condition:
        $exit_0 and 
        any of ($requests_import, $subprocess_import)
}