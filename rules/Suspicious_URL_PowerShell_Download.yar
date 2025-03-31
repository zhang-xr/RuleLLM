rule Suspicious_URL_PowerShell_Download {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands downloading files from suspicious domains like 000webhostapp.com"
        confidence = 85
        severity = 75

    strings:
        $url = "000webhostapp.com" nocase
        $powershell = "powershell" nocase
        $invoke_webrequest = "Invoke-WebRequest" nocase
        $outfile = "-OutFile" nocase

    condition:
        all of them
}