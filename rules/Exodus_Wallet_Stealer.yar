rule Exodus_Wallet_Stealer {
    meta:
        author = "RuleLLM"
        description = "Detects malicious code targeting Exodus wallet files for exfiltration"
        confidence = 90
        severity = 95

    strings:
        $path1 = "C:\\Users\\" ascii wide
        $path2 = "\\appdata\\roaming\\exodus\\" ascii wide
        $wallet_files = /exodus\.(wallet|conf\.json|info\.seco|passphrase\.json|seed\.seco|storage\.seco|twofactor\.seco|twofactor-secret\.seco)/ ascii wide
        $telegram_api = "https://api.telegram.org/bot" ascii wide
        $ip_api = "http://ip-api.com/line/?fields=" ascii wide

    condition:
        all of ($path1, $path2) and 
        2 of ($wallet_files) and 
        ($telegram_api or $ip_api)
}