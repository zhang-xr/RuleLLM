rule PowerShell_Base64_Execution_In_Python {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded PowerShell commands in Python scripts"
        confidence = 92
        severity = 88
        
    strings:
        $base64_start = /SQ[a-zA-Z0-9+\/]{10,}={0,2}/
        $powershell = "powershell" nocase
        $encoded_cmd = "-EncodedCommand" nocase
        
    condition:
        $powershell and $encoded_cmd and $base64_start and 
        #base64_start > 1 and 
        filesize < 20KB
}