rule Base64_Executable_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded payloads that download and execute binaries"
        confidence = 85
        severity = 75

    strings:
        $base64_code = /b[a-zA-Z0-9+\/]+={0,2}/
        $exec_call = "subprocess.call"
        $requests_get = "requests.get"
        $tempfile = "tempfile.NamedTemporaryFile"

    condition:
        all of ($base64_code, $exec_call, $requests_get, $tempfile)
}