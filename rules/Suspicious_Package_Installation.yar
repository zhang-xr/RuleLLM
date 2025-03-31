rule Suspicious_Package_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious installation of Python packages using os.system."
        confidence = 75
        severity = 70

    strings:
        $os_system_pip = /os\.system\(\"pip install [^\"]+ -q -q -q\"\)/
        $install_requires = "install_requires"

    condition:
        $os_system_pip and $install_requires
}