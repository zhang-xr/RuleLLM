rule Malicious_Package_Install_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup.py files that override install or egg_info commands to execute arbitrary code"
        confidence = 90
        severity = 80
    strings:
        $cmdclass = "cmdclass"
        $install = "install"
        $egg_info = "egg_info"
        $setup = "setup("
        $class_run = "class .*?(install|egg_info).*?run"
        $http_request = "requests.get"
    condition:
        all of ($cmdclass, $setup) and 
        any of ($install, $egg_info) and
        $class_run and
        $http_request
}