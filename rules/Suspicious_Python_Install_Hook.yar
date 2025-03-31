rule Suspicious_Python_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package installation hooks that execute additional code"
        confidence = 85
        severity = 75

    strings:
        $install_hook = "cmdclass={'install': Trace}"
        $install_run = "install.run(self)"
        $subprocess_call = "subprocess.call([sys.executable"

    condition:
        all of them and 
        filesize < 10KB
}