rule Python_Malicious_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup configurations"
        confidence = 85
        severity = 75
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass={'install':"
        $custom_install = "CustomInstall"
        $http_import = "import requests"
    condition:
        all of them and filesize < 15KB
}