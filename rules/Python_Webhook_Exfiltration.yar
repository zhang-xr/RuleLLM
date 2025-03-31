rule Python_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with webhook-based data exfiltration"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class PostInstallCommand(install)"
        $webhook_url = /https?:\/\/[^\s]+webhook[^\s]+/
        $platform_import = "import platform"
        $requests_import = "import requests"
        $ip_lookup = /https?:\/\/httpbin\.org\/ip/
    condition:
        all of them and filesize < 10KB
}