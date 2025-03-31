rule Malicious_Python_Base64_Powershell {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded PowerShell commands in Python scripts"
        confidence = 90
        severity = 85
    
    strings:
        $base64_powershell = /powershell\s+-EncodedCommand\s+[A-Za-z0-9+\/]+=*/
        $subprocess_popen = "subprocess.Popen"
    
    condition:
        all of them and filesize < 10KB
}