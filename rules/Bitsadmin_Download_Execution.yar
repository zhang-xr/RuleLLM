rule Bitsadmin_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects bitsadmin usage for downloading and executing files"
        confidence = 85
        severity = 85
    strings:
        $bitsadmin = "bitsadmin"
        $transfer = /\/transfer \w+/
        $download = /\/download/
        $url = /https?:\/\/[^\s]+/
        $exe_path = /\.exe\"/
    condition:
        all of ($bitsadmin, $transfer, $download) and any of ($url, $exe_path)
}