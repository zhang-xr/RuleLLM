rule Malicious_Python_Setup_File_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that attempt to modify system files like /etc/passwd or user profile files during installation."
        confidence = 90
        severity = 85

    strings:
        $setup_import = "from distutils.core import setup"
        $install_class = "class gpl(install):"
        $file_path = "/etc/passwd"
        $profile_path = ".profile"
        $chr_join = "''.join([chr(x) for x in ["
        $file_write = "with open(f'/{r}/{u}/{p}','a') as k:"
        $file_read = "with open(f'/{r}/{u}/{p}','r'):"

    condition:
        all of ($setup_import, $install_class) and 
        (2 of ($file_path, $profile_path, $chr_join, $file_write, $file_read))
}