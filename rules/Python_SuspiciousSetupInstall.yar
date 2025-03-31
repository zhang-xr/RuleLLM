rule Python_SuspiciousSetupInstall {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py installation patterns"
        confidence = 85
        severity = 80
        reference = "Custom installation class with overridden run method"
    
    strings:
        $custom_install = "class CustomInstallCommand(install)"
        $override_run = "def run(self):"
        $setup_call = "setup("
        $long_desc = "long_description"
        
    condition:
        all of them and 
        filesize < 100KB
}