rule Hardcoded_Random_Package_Name {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded random package names"
        confidence = 80
        severity = 70

    strings:
        $package_name = /[a-z0-9]{20,}/ nocase

    condition:
        $package_name
}