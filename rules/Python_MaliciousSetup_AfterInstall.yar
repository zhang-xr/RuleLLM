rule Python_MaliciousSetup_AfterInstall {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py with custom AfterInstall command"
        confidence = 90
        severity = 80
    strings:
        $install_class = /class\s+\w+\(\s*install\s*\):/
        $run_method = /def\s+run\s*\(self\):/
        $os_system = /os\.system\(/
        $base64_decode = /base64\.b64decode\(/
        $cmdclass = /cmdclass\s*=\s*{/
    condition:
        all of them and
        filesize < 10KB
}