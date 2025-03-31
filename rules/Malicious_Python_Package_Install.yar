rule Malicious_Python_Package_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation with custom install class"
        confidence = 95
        severity = 90
    strings:
        $install_class = /class \w+InstallStrat\(install\):/ nocase
        $cmdclass = /cmdclass\s*=\s*\{['"]install['"]:\s*\w+InstallStrat\}/ nocase
        $main_call = /from \w+ import main\s*main\(\)/ nocase
        $setup = /setup\(/ nocase
    condition:
        all of them and filesize < 10KB
}