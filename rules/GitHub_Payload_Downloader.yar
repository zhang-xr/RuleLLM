rule GitHub_Payload_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects scripts downloading executables from GitHub raw URLs"
        confidence = "90"
        severity = "85"
    
    strings:
        $github_raw = /github\.com\/[^\/]+\/[^\/]+\/raw\//
        $exe_file = /\.exe[\"\']/
        $powershell = "powershell" nocase
        $hidden_window = "-WindowStyle Hidden"
        
    condition:
        $github_raw and $exe_file and 
        ($powershell or $hidden_window)
}