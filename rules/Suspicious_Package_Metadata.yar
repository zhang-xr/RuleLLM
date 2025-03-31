rule Suspicious_Package_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package metadata with random-looking strings"
        confidence = 80
        severity = 70

    strings:
        $random_description = /DESCRIPTION = '[A-Za-z0-9]{20,}'/
        $random_long_description = /LONG_DESCRIPTION = '[A-Za-z0-9]{100,}'/
        $random_author = /author="[A-Za-z0-9]{5,}"/
        $random_email = /author_email="[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]{2,}"/

    condition:
        any of ($random_description, $random_long_description, $random_author, $random_email)
}