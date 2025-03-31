rule Python_DynamicImport_SystemInfoExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that dynamically imports modules, gathers system info, and potentially exfiltrates data"
        confidence = 90
        severity = 85
    strings:
        $importlib_import = "importlib.import_module"
        $getattr = "getattr"
        $os_functions = /(getlogin|getcwd)/ ascii
        $socket_functions = /(gethostbyname|gethostname)/ ascii
        $base64_ops = /base64\.(b64decode|urlsafe_b64encode)/ ascii
        $install_class = "class CustomInstallCommand"
        $datetime_check = "datetime.datetime.now()"
    condition:
        all of ($importlib_import, $getattr) and 
        2 of ($os_functions, $socket_functions) and 
        $base64_ops and 
        $install_class and 
        $datetime_check
}