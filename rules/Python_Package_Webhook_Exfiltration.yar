rule Python_Package_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that exfiltrate system data to a webhook during installation."
        confidence = "90"
        severity = "80"
    strings:
        $webhook_url = /https:\/\/webhook\.site\/[a-f0-9\-]{36}/ ascii wide
        $post_install_class = "class PostInstallCommand" ascii wide
        $send_function = "def send():" ascii wide
        $requests_import = "import requests" ascii wide
        $setup_function = "setup(" ascii wide
    condition:
        all of them and
        $webhook_url and $post_install_class and $send_function and $setup_function
}