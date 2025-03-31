rule Malicious_Python_Setup_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup files with custom install commands that send data to external webhooks."
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstallCommand(install):"
        $requests_import = "import requests"
        $webhook_url = /https?:\/\/[^\s]+/  // Matches any HTTP/HTTPS URL
        $post_request = "requests.post("
        $setup_function = "setup("
    condition:
        all of ($install_class, $requests_import, $post_request, $setup_function) and
        $webhook_url
}