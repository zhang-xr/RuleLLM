rule Setup_Py_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of setup.py to execute malicious code during installation"
        confidence = 90
        severity = 85

    strings:
        $cmdclass = "cmdclass"
        $post_install = "PostInstallCommand"
        $install = "install"

    condition:
        all of ($cmdclass, $post_install, $install)
}