rule Malicious_PostInstall_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious post-installation code execution involving URL fetching and file writing."
        confidence = 90
        severity = 80

    strings:
        $atexit_register = "atexit.register"
        $urlopen = "urllib.request.urlopen"
        $open_write = "open(..., 'wb')"
        $base64_encode = "base64.b64encode"

    condition:
        all of them and
        filesize < 10KB
}