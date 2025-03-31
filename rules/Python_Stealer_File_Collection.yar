rule Python_Stealer_File_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based file collection patterns for Exodus wallet"
        confidence = 90
        severity = 85
    strings:
        $getuser = "getpass.getuser()" ascii
        $appdata = "os.getenv('APPDATA')" ascii
        $zipfile = "ZipFile(zip, \"w\")" ascii
        $wallet_files = /(exodus\.conf\.json|info\.seco|passphrase\.json|seed\.seco)/ ascii
        $file_check = "os.path.exists" ascii
    condition:
        all of them and filesize < 150KB
}