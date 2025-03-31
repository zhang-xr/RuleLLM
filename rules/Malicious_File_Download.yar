rule Malicious_File_Download {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of malicious file downloads via encoded commands"
        confidence = "95"
        severity = "90"
    
    strings:
        $http_pattern = /https?:\/\/[^\s]+/
        $encoded_cmd = /SQBuAHQAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0/
        $outfile = "-OutFile"
    
    condition:
        $http_pattern and $encoded_cmd and $outfile
}