rule Python_Setup_RemotePayload {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that attempt to download and execute remote payloads."
        confidence = 85
        severity = 90

    strings:
        $setup = "setup("
        $tempfile = "NamedTemporaryFile"
        $urlopen = "urlopen"
        $exec = "exec("
        $remote_url = /https?:\/\/[^\s]+\.(raw|txt|py)/

    condition:
        all of ($setup, $tempfile, $urlopen, $exec) and 
        $remote_url
}