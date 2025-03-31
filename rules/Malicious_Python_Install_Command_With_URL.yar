rule Malicious_Python_Install_Command_With_URL {
    meta:
        author = "RuleLLM"
        description = "Detects a custom Python install command that sends a POST request to a specific remote URL, indicative of data exfiltration."
        confidence = 90
        severity = 80

    strings:
        $install_class = "class CustomInstallCommand(install):"
        $subprocess_run = /subprocess\.run\(\[.*?\]\, capture_output=True\, text=True\)/
        $post_request = /requests\.post\(.*?\, data=.*?\)/
        $remote_url = "https://vigneshsb.me/test.php"

    condition:
        all of them
}