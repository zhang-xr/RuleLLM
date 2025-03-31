rule Malicious_Python_Powershell_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using PowerShell to download and execute external files"
        confidence = "90"
        severity = "80"
    strings:
        $python_import = "import subprocess"
        $powershell_cmd = "powershell -WindowStyle Hidden -EncodedCommand"
        $invoke_webrequest = "Invoke-WebRequest" nocase
        $base64_pattern = /SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0/
    condition:
        all of them
}