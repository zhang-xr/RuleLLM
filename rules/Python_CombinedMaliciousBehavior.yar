rule Python_CombinedMaliciousBehavior {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with combined malicious behavior patterns"
        confidence = 95
        severity = 90
    strings:
        $url1 = "http://dnipqouebm-psl.cn.oast-cn.byted-dast.com001"
        $url2 = "http://oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $url3 = "http://sbfwstspuutiarcjzptf0rueg2x53eh2c.oast.fun"
        $hostname = "platform.node()"
        $username = "getpass.getuser()"
        $current_path = "os.getcwd()"
        $install_hook = "class CrazyInstallStrat(install):"
        $run_method = "def run(self):"
        $malicious_exec = "from main import main"
    condition:
        (1 of ($url1, $url2, $url3)) and
        (1 of ($hostname, $username, $current_path)) and
        ($install_hook and $run_method and $malicious_exec)
}