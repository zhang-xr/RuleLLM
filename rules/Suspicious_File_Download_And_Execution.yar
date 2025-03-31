rule Suspicious_File_Download_And_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects downloading and executing a file from a remote URL"
        confidence = 95
        severity = 90

    strings:
        $requests_get = "requests.get(" ascii
        $tempfile_write = "tmp_file.write(" ascii
        $subprocess_call = "subprocess.call(" ascii
        $http_url = /https?:\/\/[^\s]+\.exe/ ascii

    condition:
        all of ($requests_get, $tempfile_write, $subprocess_call) and 
        $http_url
}