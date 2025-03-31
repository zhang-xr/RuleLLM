rule Powershell_EncodedDownloader {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands with Base64-encoded download-and-execute payloads"
        confidence = 95
        severity = 90

    strings:
        $subprocess_popen = "subprocess.Popen"
        $powershell_encoded = /powershell.*-EncodedCommand/
        $invoke_webrequest = "Invoke-WebRequest"
        $windowstyle_hidden = "-WindowStyle Hidden"
        $base64_payload = /SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0/

    condition:
        all of them
}