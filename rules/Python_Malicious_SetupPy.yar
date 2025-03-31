rule Python_Malicious_SetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious patterns in setup.py files including custom install commands and system info gathering"
        confidence = 95
        severity = 90
    strings:
        $setup = "setup("
        $custom_install = "cmdclass={'install':"
        $system_info = /(getlogin|gethostname|getcwd)/ ascii
        $requires = /(install_requires|setup_requires)=.*requests/ ascii
    condition:
        $setup and 
        $custom_install and 
        2 of ($system_info, $requires)
}