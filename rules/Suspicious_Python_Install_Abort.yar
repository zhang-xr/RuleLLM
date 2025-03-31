rule Suspicious_Python_Install_Abort {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that override install command to abort installation with suspicious messages"
        confidence = "90"
        severity = "80"
    
    strings:
        $class_def = "class AbortInstall(install):"
        $raise_exit = "raise SystemExit"
        $install_override = "cmdclass = {'install': AbortInstall}"
        $suspicious_message = "[+] It looks like you try to install"
    
    condition:
        all of them and filesize < 10KB
}