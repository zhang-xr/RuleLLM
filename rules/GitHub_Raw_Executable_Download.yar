rule GitHub_Raw_Executable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects downloads of executable files from GitHub raw content"
        confidence = 95
        severity = 90
    strings:
        $github_raw = /https:\/\/github\.com\/[^\/]+\/[^\/]+\/raw\/[^\/]+\/[^\/]+\.exe/
        $output_file = /os\.path\.join\(os\.getcwd\(\),\s+"[^"]+\.exe"\)/
    condition:
        all of them
}