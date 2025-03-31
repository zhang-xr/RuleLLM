rule Suspicious_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file download and execution patterns"
        confidence = 95
        severity = 90
    strings:
        $remote_url = /https?:\/\/[^\s]+\.exe/
        $file_write = /open\(.*,\s*['"]wb['"]\)\.write\(/
        $file_execute = /call\(.*\.exe\)/
    condition:
        all of them
}