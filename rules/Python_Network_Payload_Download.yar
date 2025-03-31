rule Python_Network_Payload_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts attempting to download payloads from external URLs"
        confidence = 80
        severity = 75

    strings:
        $url_indicator = /https?:\/\/[^\s"]+\/[^\s"]+\?download/
        $requests_import = "import requests"
        $subprocess_import = "import subprocess"

    condition:
        $url_indicator and ($requests_import or $subprocess_import)
}