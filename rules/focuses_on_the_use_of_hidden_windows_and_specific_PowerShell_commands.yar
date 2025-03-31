rule focuses_on_the_use_of_hidden_windows_and_specific_PowerShell_commands {
    meta:
        description = "focuses on the use of hidden windows and specific PowerShell commands"
        confidence = "90"
        severity = "85"

    strings:
        $hidden_window = "-WindowStyle Hidden"
        $download_command = "Invoke-WebRequest"
        $outfile = "-OutFile"

    condition:
        all of them
}