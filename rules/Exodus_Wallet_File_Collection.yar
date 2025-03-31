rule Exodus_Wallet_File_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to collect Exodus wallet files"
        confidence = 90
        severity = 85
    strings:
        $exodus_path = "appdata\\roaming\\exodus"
        $wallet_files = /exodus\.(conf\.json|wallet\\[a-z]+\.(seco|json))/
    condition:
        all of them
}