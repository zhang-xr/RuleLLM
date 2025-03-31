rule Python_InstallHook_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation hooks"
        confidence = 95
        severity = 90
    strings:
        $install_class = /class\s+\w+\(install\):/ ascii wide
        $cmdclass = "cmdclass={'install'" ascii wide
        $run_method = "def run(self):" ascii wide
        $import_main = "from main import main" ascii wide
    condition:
        all of them and filesize < 15KB
}