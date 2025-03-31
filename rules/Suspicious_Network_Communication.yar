rule Suspicious_Network_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious network communication patterns, including URL fetching and response reading."
        confidence = 85
        severity = 75

    strings:
        $urlopen = "urllib.request.urlopen"
        $response_read = "response.read()"
        $context = "context=ssl_context"

    condition:
        all of them
}