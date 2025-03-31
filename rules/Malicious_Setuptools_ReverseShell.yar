rule Malicious_Setuptools_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setuptools abuse with reverse shell creation"
        confidence = 90
        severity = 95

    strings:
        $setuptools_import = "from setuptools import setup"
        $install_class = "class CustomInstall(install)"
        $reverse_shell = /s\.connect\(\([\'\"].*[\'\"],\s*\d+\)\)/
        $base64_exec = /os\.system\(\'echo\s+%s\|base64\s+-d\|bash\'/

    condition:
        all of them
}