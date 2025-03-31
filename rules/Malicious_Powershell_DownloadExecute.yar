rule Malicious_Powershell_DownloadExecute {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands downloading and executing executables via Python"
        confidence = 95
        severity = 90
        reference = "Analyzed code segment"
    
    strings:
        $download_cmd = /curl\.exe\s+-L\s+https:\/\/[^\s]+\s+-o\s+"[^"]+"/
        $execute_cmd = /Start-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $powershell_call = "subprocess.run([\"powershell\", \"-Command\""
        $output_file = "os.path.join(os.getcwd(),"
    
    condition:
        all of ($powershell_call, $output_file) and
        (1 of ($download_cmd, $execute_cmd))
}