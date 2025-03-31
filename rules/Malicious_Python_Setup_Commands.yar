rule Malicious_Python_Setup_Commands {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup commands that execute custom code during installation"
        confidence = 85
        severity = 90

    strings:
        $custom_install = "cmdclass={ 'install': CustomInstallCommand"
        $custom_develop = "cmdclass={ 'develop': CustomDevelopCommand"
        $custom_egg_info = "cmdclass={ 'egg_info': CustomEggInfoCommand"
        $os_system = "os.system("
        $curl_command = /curl\s+-H\s+['"]Metadata-Flavor:\s+Google['"]/

    condition:
        any of ($custom_install, $custom_develop, $custom_egg_info) and 
        all of ($os_system, $curl_command)
}