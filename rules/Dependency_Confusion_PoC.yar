rule Dependency_Confusion_PoC {
    meta:
        author = "RuleLLM"
        description = "Detects potential dependency confusion attack patterns"
        confidence = 85
        severity = 80
    strings:
        $poc_description = /prove[nr]{2} concept|test purposes only|research survey/
        $suspicious_version = "9.9.9"
        $random_pkg_name = "dependency_confusion123456"
    condition:
        ($poc_description and $suspicious_version) or $random_pkg_name
}