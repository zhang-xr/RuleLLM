rule Suspicious_Package_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious metadata, such as random or meaningless descriptions and version numbers."
        confidence = 85
        severity = 70

    strings:
        $random_version = "VERSION = '1.0.0'"
        $random_description = "DESCRIPTION = 'BNmDECfZzvfblmvFOrDTOyGE'"
        $long_random_description = "LONG_DESCRIPTION = 'YDAEgwuTIFHUZHmxCbyLqDCOLRfOPrm UdYrsrRADmQzZPHTRU qLzNkKYtqleZripgyiaeGrJEyAPJiAUkbWNWsvuqOGSajjVlbUdhKBMfRIlkOBgPRKWWXwXoa duyfZPMlWbwgBlbJNupCQxiXCBtbQHKRikGBeUxoWnuGaXd'"
        $random_author = "author=\"LIUsdUSKcin\""
        $random_email = "author_email=\"yiXxRgaszcicYveblxrv@gmail.com\""

    condition:
        all of ($random_version, $random_description, $long_random_description, $random_author, $random_email)
}