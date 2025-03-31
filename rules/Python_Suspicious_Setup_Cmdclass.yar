rule Python_Suspicious_Setup_Cmdclass {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py scripts using cmdclass to override default commands"
        confidence = "75"
        severity = "60"
    
    strings:
        $setup_call = "setup("
        $cmdclass_key = /['\"]cmdclass['\"]\s*:/
        $install_key = /['\"]install['\"]\s*:/
    
    condition:
        $setup_call and $cmdclass_key and $install_key
}