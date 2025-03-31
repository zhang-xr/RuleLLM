import re
import logging
from typing import Optional, List
from rulegen.client import LLMClient as BaseClient

class Refiner:
    def __init__(self):
        """Initialize YaraGenerator with LLM client"""
        self.llm_client = BaseClient()
        self.logger = logging.getLogger(__name__)

    def generate_rule_from_content(self, content: str, rule_type: str = "yara") -> Optional[List[str]]:
        """Generate rules from given content
        
        Args:
            content (str): The content to analyze
            rule_type (str): Type of rules to generate ("yara" or "semgrep")
            
        Returns:
            Optional[List[str]]: List of generated rules, or None if generation failed
        """
        try:
            system_message = self._get_system_prompt(rule_type)
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": f"Analyze and generate for the following content :\n{content}"}
            ]
            
            response_content = self.llm_client.invoke(messages)
            self.logger.info(f"Refiner response:\n{response_content}")
            
            if rule_type == "yara":
                return self._extract_yara_rule(response_content)
            elif rule_type == "semgrep":
                return self._extract_semgrep_rule(response_content)
            else:
                self.logger.error(f"Unsupported rule type: {rule_type}")
                return None
            
        except Exception as e:
            self.logger.error(f"Failed to generate {rule_type} rule: {str(e)}")
            return None

    def _get_system_prompt(self, rule_type: str) -> str:
        """Get the system prompt for the specified rule type"""
        if rule_type == "yara":
            return """You are a YARA rule expert. Your task is to analyze similar malicious code samples provided by the user and create generic YARA rules that can detect this malware family. The rules should detect based on malicious behavioral characteristics rather than over-relying on static features. Please follow these steps:

1. Deep analysis of malicious behavior:
- Identify core malicious functionality and behavioral patterns
- Analyze key execution flows and API call sequences  
- Extract characteristic code structures of malicious operations
- Identify key algorithms or logic used to achieve malicious purposes
- Focus on dynamic behavioral characteristics (like command execution, network communication patterns, etc.)
- Avoid using common library imports or standard function calls that might appear in benign packages
- Filter out patterns that are common in normal Python packages (like requests, os, sys usage)
- Focus on suspicious combinations and sequences rather than individual API calls
- Extract common patterns across similar malicious behaviors to create more generic rules

2. Generate balanced behavior-based rules. Rules must be wrapped in ```yara and ```:
- Prioritize code patterns that reflect malicious behavior
- Build compound conditions that capture behavioral characteristics
- Focus on function call sequences and execution flow patterns
- Avoid over-reliance on easily changeable static strings
- Exclude common package patterns to reduce false positives
- Combine multiple indicators to ensure malicious intent
- Use proximity and order conditions to capture behavior sequences
- Identify and leverage commonalities between similar malicious samples to create more robust rules

3. Rule complexity guidelines:
- Each rule should contain 3-5 meaningful conditions in its condition section (e.g., $a and $b and $c)
- Avoid overly simple rules with just 1-2 conditions, as these may trigger on benign packages
- Don't create rules with too many conditions (>6), as they become brittle and hard to maintain
- Balance between specificity (to avoid false positives) and generality (to catch variants)
- Combine both string patterns and their usage context in conditions
- Include at least one behavioral indicator along with supporting patterns in each rule
- Focus on extracting common patterns that appear across multiple malicious samples

4. Regular expression format example:
Original: $pattern = /conn\.request\("POST"\, "[^"]+"\, body=/
Fixed: $pattern = /conn.request\("POST", "[^"]+", body=/

Generate YARA rules that are common in this malware family, ensuring rules contain all necessary components. Return only the generated YARA rules without explanation."""
        elif rule_type == "semgrep":
            return """You are a Semgrep rule expert. Your task is to analyze code samples and create generic Semgrep rules to detect vulnerable or malicious code patterns. The rules should detect based on behavioral characteristics rather than over-relying on static features. Please follow these steps:

1. Deep analysis of vulnerability behavior:
- Identify core vulnerable or malicious functionality and behavioral patterns
- Analyze key execution flows and API call sequences
- Extract characteristic code structures and dangerous operations
- Identify key algorithms or logic used to achieve malicious purposes
- Focus on dynamic behavioral characteristics (like command execution, network communication patterns, etc.)
- Avoid using common library imports or standard function calls that might appear in benign code
- Filter out patterns that are common in normal code
- Focus on suspicious combinations and sequences rather than individual API calls
- Extract common patterns across similar vulnerabilities to create more generic rules

2. Generate balanced behavior-based rules. Rules must be wrapped in ```yaml ```:
- Prioritize code patterns that reflect vulnerable behavior
- Build compound patterns that capture behavioral characteristics
- Focus on function call sequences and execution flow patterns
- Avoid over-reliance on easily changeable static strings
- Exclude common code patterns to reduce false positives
- Combine multiple indicators to ensure vulnerability detection
- Use pattern-inside and pattern-not-inside to capture behavior sequences
- Use metavariables (e.g., `$VAR`) and ellipsis (`...`) for flexibility
- Use `pattern-either` and `pattern-not` for robust detection
- Identify and leverage commonalities between similar vulnerable samples to create more robust rules

3. Rule complexity guidelines:
- Each rule should contain 3-5 meaningful pattern combinations
- Avoid overly simple rules with just 1-2 patterns, as these may trigger on benign code
- Don't create rules with too many patterns (>6), as they become brittle and hard to maintain
- Balance between specificity (to avoid false positives) and generality (to catch variants)
- Combine pattern matching and context conditions
- Include at least one behavioral indicator along with supporting patterns in each rule
- Focus on extracting common patterns that appear across multiple vulnerable samples

4. Rule structure requirements:
- Each rule must have:
  * A unique `id` following format: [category].[subcategory].[name]
  * A descriptive `message` explaining the issue and impact
  * A `severity` level (ERROR/WARNING/INFO)
  * Correct `languages` specification
  * Comprehensive metadata:
    - description: Detailed explanation of the vulnerability
    - references: CVE, CWE, or relevant documentation
    - author: RuleLLM
    - confidence: high/medium/low
    - category: security/correctness/performance
    - subcategory: injection/auth/crypto/etc
    - cwe: Relevant CWE IDs
- Ensure rules are maintainable and understandable

5. Pattern syntax example:
Original: pattern: $X.request("POST", $Y, body=$Z)
Improved: pattern-either:
  - pattern: $X.request("POST", $Y, body=$Z)
  - pattern: $X.request("POST", $Y, data=$Z)
  - pattern: $X.post($Y, data=$Z)

Return only the generated Semgrep rules without explanation."""
        else:
            raise ValueError(f"Unsupported rule type: {rule_type}")

    def _extract_yara_rule(self, llm_response: str) -> List[str]:
        """Extract YARA rules from LLM response"""
        # First try to extract from code blocks (both ```yara and ``` formats)
        code_block_patterns = [
            r'```yara\n(.*?)\n```',
            r'```\n(.*?)\n```'
        ]
        
        rules = []
        response_text = llm_response.strip()
        
        # Try code block patterns first
        for pattern in code_block_patterns:
            matches = re.finditer(pattern, response_text, re.DOTALL)
            for match in matches:
                potential_rule = match.group(1).strip()
                if potential_rule.startswith('rule '):
                    rules.append(potential_rule)
        
        # If no rules found in code blocks, check if response itself is a rule
        if not rules and response_text.startswith('rule '):
            rules.append(response_text)
        
        self.logger.info(f"Extracted {len(rules)} YARA rules")
        if not rules:
            self.logger.warning("No valid YARA rule found in LLM response")
            self.logger.debug(f"Response content:\n{response_text}")
        
        return rules
    
    def _extract_semgrep_rule(self, llm_response: str) -> List[str]:
        """Extract Semgrep rules from LLM response"""
        # Extract from code blocks (both ```yaml and ``` formats)
        code_block_patterns = [
            r'```yaml\n(.*?)\n```',
            r'```\n(.*?)\n```'
        ]
        
        rules = []
        response_text = llm_response.strip()
        
        # Try code block patterns
        for pattern in code_block_patterns:
            matches = re.finditer(pattern, response_text, re.DOTALL)
            for match in matches:
                potential_rule = match.group(1).strip()
                # Check if it's a valid Semgrep rule (should contain 'rules:' or start with '- id:')
                if 'rules:' in potential_rule or potential_rule.startswith('- id:'):
                    rules.append(potential_rule)
        
        # If no rules found in code blocks but response contains 'rules:', it might be a raw rule
        if not rules and 'rules:' in response_text:
            rules.append(response_text)
        
        self.logger.info(f"Extracted {len(rules)} Semgrep rules")
        if not rules:
            self.logger.warning("No valid Semgrep rule found in LLM response")
            self.logger.debug(f"Response content:\n{response_text}")
        
        return rules



