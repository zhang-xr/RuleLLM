rule Python_Setuptools_Malicious_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools command hooks in Python packages"
        confidence = 95
        severity = 90
    strings:
        $setup = "setup(" ascii wide
        $cmdclass = "cmdclass={" ascii wide
        $post_install = "PostInstallCommand" ascii wide
        $post_develop = "PostDevelopCommand" ascii wide
        $execute = "execute()" ascii wide
    condition:
        all of ($setup, $cmdclass) and 
        (1 of ($post_install, $post_develop)) and 
        $execute and 
        filesize < 10KB
}