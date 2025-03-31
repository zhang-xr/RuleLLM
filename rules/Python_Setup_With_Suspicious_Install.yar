rule Python_Setup_With_Suspicious_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with potentially malicious install commands"
        confidence = 80
        severity = 70
    strings:
        $setup = "setup(" nocase
        $cmdclass = "cmdclass={" nocase
        $install = "'install':" nocase
    condition:
        all of them and filesize < 10KB
}