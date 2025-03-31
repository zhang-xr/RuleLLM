rule Suspicious_File_Download {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file download from a remote server"
        confidence = 85
        severity = 75
    strings:
        $urllib_urlopen = "urllib.request.urlopen"
        $file_write = /open\([^,]+,\s*['"]wb['"]\)/
        $remote_url = /https?:\/\/[^\s]+\.(png|jpg|exe|dll)/
    condition:
        all of them
}