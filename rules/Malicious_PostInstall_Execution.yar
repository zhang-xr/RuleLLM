rule Malicious_PostInstall_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects code that registers post-installation execution using atexit"
        confidence = 90
        severity = 80
    strings:
        $atexit_register = "atexit.register"
        $setup = "setup("
        $cmdclass = "cmdclass="
    condition:
        all of them
}