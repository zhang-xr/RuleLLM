rule Suspicious_Python_Setup_PostInstall {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with post-install code execution"
        confidence = 90
        severity = 85

    strings:
        $install_class = "class CustomInstallCommand(install):"
        $post_install = /run\(self\)\s*[\n\r\s]*os\.system\(.*\)/

    condition:
        $install_class and $post_install
}