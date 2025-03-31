rule Python_HTTP_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code downloading and executing binaries"
        confidence = 90
        severity = 80
    strings:
        $requests = "import requests"
        $subprocess = "import subprocess"
        $get_request = "requests.get"
        $popen = "subprocess.Popen"
        $binary_write = "with open(.*, 'wb')"
    condition:
        filesize < 10KB and
        all of ($requests, $subprocess) and
        2 of ($get_request, $popen, $binary_write)
}