import configparser
from openai import OpenAI

def get_api_key():
    config = configparser.ConfigParser()
    config.read('config.ini')
    try:
        return config['Settings']['Model'],config['Settings']['ModelApiKey'],config['Settings']['BaseURL']
    except KeyError:
        raise KeyError("Cannot find 'ModelApiKey' in 'Settings' section of config.ini")

class LLMClient:
    def __init__(self):
        self.model, self.client = self._create_openai_client()
    
    def _create_openai_client(self):
        model, api_key, base_url = get_api_key()
        try:
            client = OpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=600,
            )
            return model, client
        except Exception as e:
            print(f"[OpenAI] Failed to create client: {str(e)}")
            raise

    def invoke(self, messages):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                seed=42
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"[OpenAI] Chat completion failed: {str(e)}")
            raise

if __name__ == "__main__":
    llm_client = LLMClient()
    messages = [
        {"role": "user", "content": "Hello, what is your name?"}
    ]
    response = llm_client.invoke(messages)
    print(response)