rule Suspicious_Package_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects custom package installation hooks that execute additional code"
        confidence = 90
        severity = 80
    strings:
        $setup = "from setuptools import setup"
        $install_hook = "cmdclass={'install':"
        $subprocess = "subprocess.call([sys.executable, \"-m\","
    condition:
        all of them
}