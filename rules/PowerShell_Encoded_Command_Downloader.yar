rule PowerShell_Encoded_Command_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell encoded commands used for downloading and executing files"
        confidence = 90
        severity = 85
    
    strings:
        $encoded_cmd = /powershell\s+-[Ee]ncodedCommand\s+[A-Za-z0-9+\/]+={0,2}/
        $web_request = /Invoke-[Ww]eb[Rr]equest/ nocase
        $outfile_pattern = /-OutFile\s+["'][^"']+["']/ nocase
        $hidden_window = /-WindowStyle\s+Hidden/ nocase
        
    condition:
        any of ($encoded_cmd, $web_request) and 
        any of ($outfile_pattern, $hidden_window)
}