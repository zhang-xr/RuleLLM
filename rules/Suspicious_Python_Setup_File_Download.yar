rule Suspicious_Python_Setup_File_Download {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file downloads in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $powershell = "powershell -Command"
        $invoke_webrequest = "Invoke-WebRequest"
        $exe_file = /\.exe'/
        $http_url = /https?:\/\//
    condition:
        all of ($powershell, $invoke_webrequest) and
        any of ($exe_file, $http_url)
}