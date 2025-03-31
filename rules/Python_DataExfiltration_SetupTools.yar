rule Python_DataExfiltration_SetupTools {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup tools with data collection and exfiltration capabilities"
        confidence = 90
        severity = 80
    strings:
        $install_hook = "class new_install(install):"
        $atexit = "atexit.register(_post_install)"
        $ip_collect = "requests.get('https://api.ipify.org')"
        $base64_encode = "base64.b64encode"
        $remote_request = /requests\.get\s*\(\s*[\"'].+[\"']\s*\+\s*base64_message/
    condition:
        all of them
}