rule Python_TrojanizedPackage_setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious usage of setup() function in Python scripts, often used in trojanized packages"
        confidence = 75
        severity = 90

    strings:
        $setup = "setup(" ascii
        $install_requires = "install_requires" ascii
        $exec = "exec(" ascii

    condition:
        all of ($setup, $install_requires) and 1 of ($exec)
}