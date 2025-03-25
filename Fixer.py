import os
import uuid
import subprocess
from typing import Optional, List, Tuple
import yara
import logging
import re
from client import LLMClient as BaseClient

class Fixer:
    def __init__(self):
        """Initialize Fixer with LLM client"""
        self.llm_client = BaseClient()
        self.logger = logging.getLogger(__name__)

    def fix_rule(self, rule_content: str, rule_type: str = "yara", max_retries: int = 3) -> tuple[Optional[str], list]:
        """
        Fix a single rule (YARA or Semgrep) with retries
        
        Args:
            rule_content (str): The rule content to fix
            rule_type (str): Type of rule to fix ("yara" or "semgrep")
            max_retries (int): Maximum number of fix attempts
            
        Returns: 
            tuple[Optional[str], list]: (fixed_rule, error_messages)
        """
        current_rule = rule_content
        attempts = 0
        error_messages = []
        
        # First validate to get initial error if any
        if rule_type == "yara":
            validation_error = self._validate_yara_rule(current_rule)
        elif rule_type == "semgrep":
            validation_error = self._validate_semgrep_rule(current_rule)
        else:
            return None, [f"Unsupported rule type: {rule_type}"]
            
        initial_message = f"Fix this {rule_type.upper()} rule that has the following error:\n{validation_error}\n\nRule:\n{current_rule}"
        
        self.logger.info(f"Starting {rule_type} rule fixing process")
        self.logger.debug(f"Initial validation error: {validation_error}")
        
        # Initialize conversation with system message and first rule with error
        messages = [
            {"role": "system", "content": self._get_system_message(rule_type)},
            {"role": "user", "content": initial_message}
        ]

        while attempts < max_retries:
            if rule_type == "yara":
                validation_error = self._validate_yara_rule(current_rule)
            else:
                validation_error = self._validate_semgrep_rule(current_rule)
                
            if not validation_error:
                self.logger.info("Rule successfully fixed")
                self.logger.info(f"Fixed rule:\n{current_rule}")
                return current_rule, error_messages

            attempts += 1
            print(f"Attempt {attempts}: {validation_error}")
            error_message = f"Attempt {attempts}: {validation_error}"
            error_messages.append(error_message)
            self.logger.debug(f"Fix attempt {attempts}: {validation_error}")
            
            # Get fixed rule from LLM
            try:
                response_content = self.llm_client.invoke(messages)
                print(f"Response content:\n {response_content}")
                
                if rule_type == "yara":
                    fixed_rules = self._extract_yara_rule(response_content)
                else:
                    fixed_rules = self._extract_semgrep_rule(response_content)
                
                if not fixed_rules:
                    error_msg = f"No valid {rule_type.upper()} rule found in LLM response"
                    self.logger.error(error_msg)
                    error_messages.append(error_msg)
                    continue
                
                current_rule = fixed_rules[0]
                print(f"Fixed rule: {current_rule}")
                # Add assistant's response and new error to conversation history
                messages.append({"role": "assistant", "content": current_rule})
                if attempts < max_retries:  # Only add new error if we're continuing
                    messages.append({"role": "user", "content": f"Error still exists: {validation_error}"})
                
            except Exception as e:
                error_msg = f"LLM error: {str(e)}"
                self.logger.error(error_msg)
                error_messages.append(error_msg)
                break

        self.logger.warning(f"Failed to fix {rule_type} rule after maximum retries")
        return None, error_messages

    def _get_system_message(self, rule_type: str) -> str:
        """Get system message for rule fixing based on rule type"""
        if rule_type == "yara":
            return """You are a YARA rule expert. Your task is to fix YARA rules based on compilation error messages to make them successfully compile. Rules must be wrapped in ```yara and ```.

When you receive a YARA rule and compilation error message, carefully analyze the error and make fixes. Here are some common errors and fixing guidelines:

1. Syntax Error Fixes:
- 'syntax error, unexpected end of file' - Usually due to:
  * Missing closing brace '}'
  * Rule terminates prematurely 
  * Strings not properly closed
  * Multi-line string format errors
- Common condition statement errors:
  * Don't use abbreviated forms like 'all of them\n}'
  * Ensure condition statements are complete and clear
  * Avoid unnecessary line breaks in condition statements
- Quote issues:
  * Mismatched quotes - Check if string definitions have paired quotes
  * Wrong quote type - Use correct quote types (single/double)
  * Escaping quotes - Quotes within strings need proper escaping
  * Multi-line strings - Ensure multi-line strings use correct quote format
- Regex syntax errors:
  * Unescaped special characters
  * Incorrect character class definitions [...]
  * Quantifier usage errors (*, +, ?, {n,m})
  * Capture group syntax errors
    * Regular expression format adjustment:

    The $http_post_pattern in the original rule uses unnecessary escaping:
    Original rule: $http_post_pattern = /conn\.request\("POST"\, "[^"]+"\, body=/
    Fixed: $http_post_pattern = /conn.request\("POST", "[^"]+", body=/
    The escaped backslashes are redundant for YARA regex and removing them better follows standard regex syntax.
- Condition statement syntax errors:
  * Operator usage errors (and, or, not)
  * Parentheses matching issues
  * String reference format errors
  * Numeric comparison syntax errors

2. Structure Integrity Checks:
- Ensure rule contains required sections (meta, strings, condition)
- Verify all referenced string identifiers are defined in strings section
- Check condition statement logical completeness
- Ensure meta field format is correct
- Rule naming conventions:
  * Cannot start with numbers
  * Cannot contain special characters
  * Cannot use reserved keywords
- Variable naming conventions:
  * String identifiers formatted correctly
  * Avoid duplicate identifiers
  * Don't use reserved words as identifiers

3. Fixing Principles:
- Fix strictly according to compilation error messages
- Maintain original detection logic
- Don't change string contents and identifiers
- Preserve original meta information
- Only fix issues causing compilation failure
- Maintain consistent code formatting and indentation
- Ensure fixes don't introduce new errors
- Regular expression format adjustment:
Original rule: $http_post_pattern = /conn\.request\("POST"\, "[^"]+"\, body=/
Fixed: $http_post_pattern = /conn.request\("POST", "[^"]+", body=/
The escaped backslashes are redundant for YARA regex and removing them better follows standard regex syntax.

Please return the complete fixed YARA rule directly, without any explanation. Rules must be wrapped in ```yara and ```. Ensure the returned rule passes YARA compiler validation."""
        elif rule_type == "semgrep":
            return """You are a Semgrep rule expert. Your task is to fix Semgrep rules based on validation error messages to make them successfully validate. Rules must be wrapped in ```yaml and ```.

When you receive a Semgrep rule and validation error message, carefully analyze the error and make fixes. Here are some common errors and fixing guidelines:

1. Syntax Error Fixes:
- YAML format errors:
  * Indentation issues
  * Missing or incorrect colons
  * Improper list formatting
  * Quote consistency issues
- Pattern syntax errors:
  * Incorrect metavariable usage
  * Invalid ellipsis placement
  * Improper pattern-either or pattern-not syntax
  * Language-specific syntax errors
- ID and metadata errors:
  * Duplicate rule IDs
  * Missing required fields
  * Improper severity levels

2. Structure Integrity Checks:
- Ensure rule contains all required sections (id, pattern, message, severity, etc.)
- Verify pattern syntax is valid for the target language
- Check that languages field contains valid language identifiers
- Ensure proper YAML structure and indentation
- Validate reference to metavariables
- Check for balanced parentheses and brackets in patterns

3. Fixing Principles:
- Fix strictly according to validation error messages
- Maintain original detection logic
- Preserve pattern structure and behavior
- Keep original metadata and descriptions
- Only fix issues causing validation failure
- Maintain consistent code formatting and indentation
- Ensure fixes don't introduce new errors

4. Common Pattern Fixes:
- Use correct quoting for string values
- Fix metavariable references ($X vs $X)
- Correct pattern syntax for target language
- Properly format multi-line patterns
- Use correct YAML syntax for lists and dictionaries
- Fix indentation while preserving meaning

Please return the complete fixed Semgrep rule directly, without any explanation. Rules must be wrapped in ```yaml and ```. Ensure the returned rule passes Semgrep validation."""
        else:
            return "Unknown rule type"

    def _validate_yara_rule(self, rule_content: str) -> str:
        """Validate YARA rule by compiling it and return error message if any"""
        try:
            # Generate unique temporary filename
            temp_file = f'temp_rule_{uuid.uuid4().hex}.yar'
            with open(temp_file, 'w') as f:
                f.write(rule_content)
            
            yara.compile(filepath=temp_file)
            
            os.remove(temp_file)
            return ""
            
        except Exception as e:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            self.logger.debug(f"YARA Compilation error: {str(e)}")
            return "YARA Compilation error: " + str(e)
    
    def _validate_semgrep_rule(self, rule_content: str) -> str:
        """Validate Semgrep rule and return error message if any"""
        try:
            # Generate unique temporary filename
            temp_file = f'temp_rule_{uuid.uuid4().hex}.yaml'
            with open(temp_file, 'w') as f:
                f.write(rule_content)
            
            # Run semgrep in validate mode
            result = subprocess.run(
                ["semgrep", "--validate", "--config", temp_file],
                capture_output=True,
                text=True
            )
            
            os.remove(temp_file)
            
            # If return code is not 0, there was an error
            if result.returncode != 0:
                return f"Semgrep validation error: {result.stderr.strip()}"
            return ""
            
        except Exception as e:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            self.logger.debug(f"Semgrep validation error: {str(e)}")
            return f"Semgrep validation error: {str(e)}"
        
    def _extract_yara_rule(self, llm_response: str) -> list[str]:
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
    
    def _extract_semgrep_rule(self, llm_response: str) -> list[str]:
        """Extract Semgrep rules from LLM response"""
        # Extract from code blocks (both ```yaml and ``` formats)
        code_block_patterns = [
            r'```+yaml\n(.*?)\n```+',  # Match 3 or more backticks with yaml
            r'```+yml\n(.*?)\n```+',   # Match 3 or more backticks with yml 
            r'```+\n(.*?)\n```+'       # Match 3 or more backticks without language
        ]
        rules = []
        response_text = llm_response.strip()
        
        # Try code block patterns
        for pattern in code_block_patterns:
            matches = re.finditer(pattern, response_text, re.DOTALL)
            for match in matches:
                potential_rule = match.group(1).strip()
                # Check if it looks like a Semgrep rule (contains 'rules:' or starts with '- id:')
                if 'rules:' in potential_rule or potential_rule.startswith('- id:'):
                    rules.append(potential_rule)
        
        # If no rules found in code blocks but response contains YAML-like structure
        if not rules and ('rules:' in response_text or '- id:' in response_text):
            # Try to extract the whole response as a rule
            rules.append(response_text)
        
        self.logger.info(f"Extracted {len(rules)} Semgrep rules")
        if not rules:
            self.logger.warning("No valid Semgrep rule found in LLM response")
            self.logger.debug(f"Response content:\n{response_text}")
        
        return rules
