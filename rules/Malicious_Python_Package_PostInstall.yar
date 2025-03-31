rule Malicious_Python_Package_PostInstall {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with malicious post-install behavior"
        confidence = 90
        severity = 80
    strings:
        $post_install = "atexit.register(_post_install)"
        $custom_install = "class CustomInstallCommand"
        $setup = "setup("
    condition:
        all of them
}