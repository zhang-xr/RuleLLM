rule Malicious_PostInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious post-install scripts in Python packages"
        confidence = 80
        severity = 85

    strings:
        $post_install_class = "class PostInstallCommand"
        $install_override = "def run(self)"
        $socket_import = "import socket"
        $subprocess_import = "import subprocess"

    condition:
        all of ($post_install_class, $install_override) and
        any of ($socket_import, $subprocess_import)
}