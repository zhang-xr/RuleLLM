rule Python_Suspicious_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup configurations"
        confidence = 90
        severity = 85
    strings:
        $setup = "setup(" ascii wide
        $cmdclass = "cmdclass=" ascii wide
        $install_requires = "install_requires=" ascii wide
        $setup_requires = "setup_requires=" ascii wide
        $version = /version\s*=\s*["']\d{3}\.\d["']/ ascii wide
    condition:
        4 of them and filesize < 15KB
}