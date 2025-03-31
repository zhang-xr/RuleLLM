rule Combined_Download_Execute_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects combined patterns of file download and execution in Python scripts"
        confidence = 95
        severity = 90

    strings:
        $download_cmd = /curl\.exe\s+-L\s+https?:\/\/[^\s]+\s+-o\s+"[^"]+"/
        $execute_cmd = /Start-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $file_path = /os\.path\.join\(os\.getcwd\(\),\s*"[^"]+"\)/

    condition:
        all of them and
        filesize < 10KB
}