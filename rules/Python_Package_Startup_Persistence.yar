rule Python_Package_Startup_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup code that downloads and persists a payload in the Windows Startup folder"
        confidence = 90
        severity = 80

    strings:
        $url_construction = /https:\/\/cdn-.*?\.repl\.co/
        $startup_path = /os\.environ\['APPDATA'\]\s*\+\s*['"]\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\/
        $subprocess_run = /subprocess\.run\(\["start",\s*[\w\.]+\],\s*shell=True\)/
        $urllib_request = /urllib\.request\.urlopen\(/

    condition:
        all of them
}