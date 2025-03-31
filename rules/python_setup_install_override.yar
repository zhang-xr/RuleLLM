rule python_setup_install_override {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that override the 'install' command to execute arbitrary code during installation."
        confidence = 90
        severity = 80

    strings:
        $class_install = "class" nocase wide ascii
        $inherit_install = ":.*install" nocase wide ascii
        $setup_func = "setup(" nocase wide ascii
        $cmdclass = "cmdclass" nocase wide ascii

    condition:
        all of them
}