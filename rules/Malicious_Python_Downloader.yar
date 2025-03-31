rule Malicious_Python_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based downloader that fetches and executes remote binaries"
        confidence = 90
        severity = 85
    strings:
        $import_requests = "import requests"
        $tempfile = "tempfile.NamedTemporaryFile"
        $subprocess = "subprocess.call"
        $http_url = /https?:\/\/[^\s]+\.(exe|dll|scr|bat|cmd)/ ascii wide
        $base64_decode = "base64.b64decode"
    condition:
        all of ($import_requests, $tempfile, $subprocess) and 
        (1 of ($http_url, $base64_decode))
}