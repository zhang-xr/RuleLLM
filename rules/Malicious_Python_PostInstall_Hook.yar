rule Malicious_Python_PostInstall_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages with post-install hooks for payload execution"
        confidence = 95
        severity = 90
    
    strings:
        $post_install = "PostInstallCommand"
        $post_develop = "PostDevelopCommand"
        $cmdclass = "cmdclass"
        $setup = "setup("
        $execute = "execute()"
    
    condition:
        $post_install and $post_develop and $cmdclass and $setup and $execute
}