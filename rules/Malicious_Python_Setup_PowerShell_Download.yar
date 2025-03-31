rule Malicious_Python_Setup_PowerShell_Download {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts using hidden PowerShell to download and execute files"
        confidence = 95
        severity = 90
    
    strings:
        $setup_import = "from distutils.core import setup"
        $powershell_cmd = "powershell -WindowStyle Hidden -EncodedCommand"
        $create_no_window = "CREATE_NO_WINDOW"
        $invoke_web = "Invoke-WebRequest" nocase
        $outfile = "-OutFile" nocase
        $try_except = "try:" wide ascii
        $pass_stmt = "pass" wide ascii
        
    condition:
        all of them and 
        filesize < 10KB and 
        #setup_import == 1 and 
        #powershell_cmd >= 1 and 
        #create_no_window >= 1
}