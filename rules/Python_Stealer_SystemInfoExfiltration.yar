rule Python_Stealer_SystemInfoExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects and exfiltrates system information during package installation"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstall(install):"
        $get_hostname = "socket.gethostname()"
        $get_user = "getpass.getuser()"
        $requests_get = "requests.get("
        $params_dict = "{'hostname':hostname,"
        $setup_py = "setup(name="
    condition:
        filesize < 2KB and
        all of them and
        #install_class in (@install_class..@install_class + 50)
}