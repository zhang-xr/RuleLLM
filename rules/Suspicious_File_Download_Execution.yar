rule Suspicious_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects patterns indicating file download and execution via PowerShell."
        confidence = 95
        severity = 90
    
    strings:
        $invoke_webrequest = "Invoke-WebRequest"
        $invoke_expression = "Invoke-Expression"
        $outfile = "-OutFile"
        $http_url = /http[s]?:\/\/[^\s"]+\.exe/
    
    condition:
        any of ($invoke_webrequest, $invoke_expression, $outfile) and $http_url
}