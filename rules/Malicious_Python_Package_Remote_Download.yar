rule Malicious_Python_Package_Remote_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that download data from remote URLs during installation"
        confidence = 85
        severity = 75
    strings:
        $urllib = "urllib.request.urlopen"
        $base64 = "base64.b64encode"
        $file_write = "open(destination, 'wb')"
    condition:
        all of them
}