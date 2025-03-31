rule Malicious_Python_Package_Installer {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installer that collects and exfiltrates system information"
        confidence = 90
        severity = 80

    strings:
        $setup_py = "from setuptools import setup, find_packages"
        $post_install = "class PostInstallScript(install)"
        $sys_path_insert = "sys.path.insert(0, 'src')"
        $data_collection = "data += json.dumps(run_test(\"git config user.email\".split(\" \"))"
        $data_exfiltration = "socket.gethostbyname(p + \".ns.depcon.buzz\")"
        $http_request = "urllib.request.Request(\"http://64.23.141.119:8080/z\""

    condition:
        all of them
}