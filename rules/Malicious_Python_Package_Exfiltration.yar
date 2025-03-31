rule Malicious_Python_Package_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages that exfiltrate data during installation using custom install commands"
        confidence = "90"
        severity = "80"

    strings:
        // Custom install command pattern
        $install_cmd = "class CustomInstallCommand(install):"
        $install_run = "def run(self):"
        $install_base = "install.run(self)"

        // Exfiltration patterns
        $requests_get = "requests.get"
        $base64_encode = "base64.b64encode"
        $http_url = /https?:\/\/[^\s"]+/ ascii wide

    condition:
        // Match custom install command and exfiltration patterns
        all of ($install_cmd, $install_run, $install_base) and
        any of ($requests_get, $base64_encode) and
        $http_url
}