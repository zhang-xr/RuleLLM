rule Malicious_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious patterns in Python setup.py files"
        confidence = 95
        severity = 90
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass"
        $post_install = "PostInstallCommand"
        $subprocess_run = "subprocess.run"
    condition:
        $setup and $cmdclass and $post_install and $subprocess_run
}