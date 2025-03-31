rule Windows_Specific_Malicious_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Windows-specific malicious installation patterns"
        confidence = 90
        severity = 85
        reference = "Windows-specific payload execution"
    
    strings:
        $os_check = "os.name == \"nt\""
        $exec_pattern = "exec("
        $requests_import = "import requests"
        $windows_classifier = "Operating System :: Microsoft :: Windows"
    
    condition:
        all of them and filesize < 10KB
}