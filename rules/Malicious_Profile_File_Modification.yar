rule Malicious_Profile_File_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to modify user profile files during package installation, a common persistence technique."
        confidence = 88
        severity = 90

    strings:
        $profile_write = "with open(f'/{r}/{u}/{p}','a') as k:"
        $profile_read = "with open(f'/{r}/{u}/{p}','r'):"
        $profile_path = ".profile"

    condition:
        all of ($profile_write, $profile_read, $profile_path)
}