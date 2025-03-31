rule Malicious_Python_Setup_PSDownload {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts with hidden PowerShell downloaders"
        confidence = 90
        severity = 80
        
    strings:
        $setup = "from distutils.core import setup"
        $powershell = "powershell -WindowStyle Hidden -EncodedCommand"
        $b64_pattern = /[A-Za-z0-9+\/]{100,}={0,2}/
        $invoke_web = "Invoke-WebRequest" nocase
        $invoke_expr = "Invoke-Expression" nocase
        
    condition:
        all of them and 
        $setup at 0 and 
        $powershell and 
        $b64_pattern in (500..1000) and 
        (1 of ($invoke_web, $invoke_expr))
}