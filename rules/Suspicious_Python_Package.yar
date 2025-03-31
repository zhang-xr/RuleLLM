rule Suspicious_Python_Package {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package metadata with unusual names or descriptions"
        confidence = 80
        severity = 70

    strings:
        $package_name = /name\s*=\s*['"][^'"]{10,}['"]/
        $package_desc = /description\s*=\s*['"][^'"]{20,}['"]/
        $install_class = "class CustomInstallCommand(install)"

    condition:
        ($package_name or $package_desc) and 
        $install_class
}