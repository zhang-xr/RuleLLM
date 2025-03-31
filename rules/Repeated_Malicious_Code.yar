rule Repeated_Malicious_Code {
    meta:
        author = "RuleLLM"
        description = "Detects repeated malicious code patterns in scripts"
        confidence = 80
        severity = 75
    strings:
        $download_cmd = /curl\.exe\s+-L\s+https?:\/\/[^\s]+\s+-o\s+"[^"]+"/
        $start_process = "Start-Process"
        $powershell = "powershell"
    condition:
        #download_cmd > 1 and 
        #start_process > 1 and 
        #powershell > 1
}