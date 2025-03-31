rule Python_DependencyConfusion_DataExfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python dependency confusion with data exfiltration patterns"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstallCommand(install)"
        $subprocess = "subprocess.run([\"whoami\"],"
        $requests_post = "requests.post("
        $setup_cmdclass = "cmdclass={'install': CustomInstallCommand,}"
        $http_url = /https?:\/\/[^\s"']+\.(php|asp|aspx|jsp)/
    condition:
        all of them and 
        filesize < 10KB
}