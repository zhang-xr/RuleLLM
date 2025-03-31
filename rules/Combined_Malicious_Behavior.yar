rule Combined_Malicious_Behavior {
    meta:
        author = "RuleLLM"
        description = "Combines detection of webhook URL, system info collection, and post-install command execution"
        confidence = 95
        severity = 90
    strings:
        $webhook_url = "https://webhook.site/17c8fbe7-886e-4f2f-8f67-1d104d430d55"
        $platform_node = "platform.node()"
        $platform_system = "platform.system()"
        $api_ipify = "requests.get('https://api.ipify.org')"
        $post_install_class = "class PostInstallCommand"
        $cmdclass = "cmdclass={'install': PostInstallCommand}"
    condition:
        3 of ($webhook_url, $platform_node, $platform_system, $api_ipify, $post_install_class, $cmdclass)
}