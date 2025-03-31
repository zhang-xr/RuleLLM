rule Malicious_Version_Check {
    meta:
        author = "RuleLLM"
        description = "Detects malicious version check and network communication"
        confidence = 85
        severity = 80

    strings:
        $get_version = /def get_version\(\):/
        $check_version = /def check_version\(\):/
        $semver = /semver\s*=\s*f"{major}\.{minor}\.{patch}"/
        $host_resolution = /doit\("socket",\s*"getho",\s*"stbyname"\)\(subdomain\)/

    condition:
        all of them
}