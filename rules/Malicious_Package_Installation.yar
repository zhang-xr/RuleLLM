rule Malicious_Package_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation patterns"
        confidence = "95"
        severity = "90"
    
    strings:
        $install_override = "class GetInstalledVersion(install)"
        $check_version_call = "check_version()"
        $datetime_check = "version_time < doit(\"datetime\", \"date\", \"time\").now()"
    
    condition:
        all of them
}