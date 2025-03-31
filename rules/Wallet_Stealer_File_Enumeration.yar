rule Wallet_Stealer_File_Enumeration {
    meta:
        author = "RuleLLM"
        description = "Detects wallet stealer malware that enumerates specific wallet files"
        confidence = 85
        severity = 90
    strings:
        $wallet_files = /C:\\Users\\.+\\appdata\\roaming\\exodus\\exodus\.wallet\\/ ascii wide
        $file_types = /(info\.seco|passphrase\.json|seed\.seco|storage\.seco|twofactor\.seco|twofactor-secret\.seco)/ ascii wide
        $os_path = "os.path.exists" ascii wide
        $zipfile = "ZipFile" ascii wide
    condition:
        all of them
}