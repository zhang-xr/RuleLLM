rule Python_Package_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that collect system information and exfiltrate it to a remote server"
        confidence = 90
        severity = 80

    strings:
        $setup_py = "from setuptools import setup"
        $install_class = "class Trace(install)"
        $subprocess_call = "subprocess.call([sys.executable"
        $http_connection = "http.client.HTTPSConnection"
        $webhook_url = "\"webhook.site\""
        $json_dumps = "json.dumps"
        $system_info = "platform.system()"
        $hostname = "socket.gethostname()"
        $installed_packages = "importlib.metadata.distributions()"

    condition:
        all of them and 
        filesize < 10KB
}