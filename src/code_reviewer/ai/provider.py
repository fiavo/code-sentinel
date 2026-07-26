"""
AI provider abstraction for code analysis.
"""

from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass


@dataclass
class AIConfig:
    """Configuration for AI provider."""
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4"
    temperature: float = 0.3
    max_tokens: int = 4096


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    @abstractmethod
    async def analyze_code(
        self,
        code: str,
        language: str,
        context: str = "",
    ) -> str:
        """
        Analyze code using AI.
        
        Args:
            code: Code to analyze
            language: Programming language
            context: Additional context
            
        Returns:
            AI analysis as string
        """
        ...
    
    @abstractmethod
    async def suggest_fix(
        self,
        code: str,
        issue: str,
        language: str,
    ) -> str:
        """
        Suggest a fix for an issue.
        
        Args:
            code: Original code
            issue: Description of the issue
            language: Programming language
            
        Returns:
            Suggested fix code
        """
        ...


class OpenAIProvider(AIProvider):
    """
    OpenAI-compatible AI provider.
    
    Works with OpenAI, Azure OpenAI, Ollama, and other compatible APIs.
    
    Example:
        provider = OpenAIProvider(
            api_key="sk-...",
            base_url="https://api.openai.com/v1",
            model="gpt-4"
        )
        analysis = await provider.analyze_code(code, "python")
    """
    
    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self._client = None
    
    async def _get_client(self):
        """Get or create httpx client."""
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
        return self._client
    
    async def analyze_code(
        self,
        code: str,
        language: str,
        context: str = "",
    ) -> str:
        """Analyze code using AI."""
        prompt = f"""You are an expert code reviewer. Analyze the following {language} code and provide:
1. A summary of the code's purpose
2. Potential issues (security, performance, bugs)
3. Suggestions for improvement
4. Overall quality assessment

{f'Context: {context}' if context else ''}

Code:
```{language}
{code}
```

Provide your analysis in a clear, structured format."""
        
        return await self._chat(prompt)
    
    async def suggest_fix(
        self,
        code: str,
        issue: str,
        language: str,
    ) -> str:
        """Suggest a fix for an issue."""
        prompt = f"""You are an expert {language} developer. Given the following code and issue, provide a fix.

Issue: {issue}

Original code:
```{language}
{code}
```

Provide only the fixed code without explanation."""
        
        return await self._chat(prompt)
    
    async def _chat(self, prompt: str) -> str:
        """Send chat completion request."""
        client = await self._get_client()
        
        response = await client.post(
            "/chat/completions",
            json={
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": "You are an expert code reviewer and software engineer."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            },
        )
        response.raise_for_status()
        
        data = response.json()
        return data["choices"][0]["message"]["content"]
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class LocalProvider(AIProvider):
    """
    Local AI provider using llama.cpp or similar.
    
    For offline code analysis without API calls.
    """
    
    def __init__(self, model_path: str = "", **kwargs):
        self.model_path = model_path
        self.kwargs = kwargs
    
    async def analyze_code(
        self,
        code: str,
        language: str,
        context: str = "",
    ) -> str:
        """Analyze code locally (placeholder)."""
        return f"[Local Analysis] Analyzed {language} code ({len(code.splitlines())} lines)"
    
    async def suggest_fix(
        self,
        code: str,
        issue: str,
        language: str,
    ) -> str:
        """Suggest fix locally (placeholder)."""
        return code  # Return original code as placeholder


def create_provider(
    provider_type: str = "openai",
    **kwargs,
) -> AIProvider:
    """
    Factory function to create AI provider.
    
    Args:
        provider_type: Provider type ("openai" or "local")
        **kwargs: Provider-specific arguments
        
    Returns:
        AIProvider instance
    """
    if provider_type == "openai":
        config = AIConfig(**kwargs)
        return OpenAIProvider(config)
    elif provider_type == "local":
        return LocalProvider(**kwargs)
    else:
        raise ValueError(f"Unknown provider type: {provider_type}")
