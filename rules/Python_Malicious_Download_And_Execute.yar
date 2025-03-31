rule Python_Malicious_Download_And_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that download and execute external executables from suspicious URLs."
        confidence = 90
        severity = 95
    strings:
        $download_pattern = /requests\.get\(["'].+["']\)/
        $execute_pattern = /os\.system\(["'].+["']\)/
        $url_pattern = /https?:\/\/[a-f0-9-]{36}\.[a-z0-9-]+\.[a-z]+\/[A-Za-z0-9_]+\.exe/
    condition:
        all of them and filesize < 10KB
}