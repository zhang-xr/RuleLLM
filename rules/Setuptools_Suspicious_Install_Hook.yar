rule Setuptools_Suspicious_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious install hooks in Python setuptools packages"
        confidence = 80
        severity = 75

    strings:
        $cmdclass = "cmdclass={'install':"
        $os_popen = "os.popen"
        $os_system = "os.system"

    condition:
        $cmdclass and ($os_popen or $os_system)
}