"""
AI-powered code analysis using OpenAI-compatible API.
"""

import os
from typing import Optional
import httpx


class AIProvider:
    """
    AI provider for code analysis using OpenAI-compatible API.
    
    Example:
        provider = AIProvider(api_key="sk-...")
        analysis = await provider.analyze_code(code)
    """
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    
    async def analyze_code(self, code: str, language: str = "python") -> dict:
        """
        Analyze code using AI.
        
        Args:
            code: Code to analyze
            language: Programming language
            
        Returns:
            Dictionary with analysis results
        """
        if not self.api_key:
            return {
                "success": False,
                "error": "API key not configured"
            }
        
        prompt = f"""Analyze this {language} code and provide:
1. A brief summary of what the code does
2. Any issues or bugs found
3. Suggestions for improvement
4. Security concerns (if any)
5. Performance tips (if any)

Code:
```{language}
{code}
```

Provide the analysis in a structured format."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [
                            {"role": "system", "content": "You are an expert code reviewer. Analyze code carefully and provide helpful feedback."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 1000,
                        "temperature": 0.7,
                    },
                    timeout=30.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    analysis = data["choices"][0]["message"]["content"]
                    return {
                        "success": True,
                        "analysis": analysis
                    }
                else:
                    return {
                        "success": False,
                        "error": f"API error: {response.status_code}"
                    }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def explain_code(self, code: str, language: str = "python") -> dict:
        """
        Explain code in detail.
        
        Args:
            code: Code to explain
            language: Programming language
            
        Returns:
            Dictionary with explanation
        """
        if not self.api_key:
            return {
                "success": False,
                "error": "API key not configured"
            }
        
        prompt = f"""Explain this {language} code in detail in Persian (Farsi):
1. What does this code do?
2. How does it work step by step?
3. What are the key concepts used?
4. Any interesting patterns or techniques?

Code:
```{language}
{code}
```

Provide a clear, educational explanation in Persian."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [
                            {"role": "system", "content": "You are a helpful programming teacher. Explain code clearly in Persian."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 1500,
                        "temperature": 0.7,
                    },
                    timeout=30.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    explanation = data["choices"][0]["message"]["content"]
                    return {
                        "success": True,
                        "explanation": explanation
                    }
                else:
                    return {
                        "success": False,
                        "error": f"API error: {response.status_code}"
                    }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def suggest_improvements(self, code: str, language: str = "python") -> dict:
        """
        Suggest code improvements.
        
        Args:
            code: Code to improve
            language: Programming language
            
        Returns:
            Dictionary with suggestions
        """
        if not self.api_key:
            return {
                "success": False,
                "error": "API key not configured"
            }
        
        prompt = f"""Suggest improvements for this {language} code:
1. Code quality improvements
2. Performance optimizations
3. Better naming conventions
4. Design patterns that could be applied
5. Alternative approaches

Code:
```{language}
{code}
```

Provide specific, actionable suggestions."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [
                            {"role": "system", "content": "You are an expert software engineer. Provide practical code improvement suggestions."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 1500,
                        "temperature": 0.7,
                    },
                    timeout=30.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    suggestions = data["choices"][0]["message"]["content"]
                    return {
                        "success": True,
                        "suggestions": suggestions
                    }
                else:
                    return {
                        "success": False,
                        "error": f"API error: {response.status_code}"
                    }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def generate_code(self, description: str, language: str = "python") -> dict:
        """
        Generate code from description.
        
        Args:
            description: Code description in Persian
            language: Target language
            
        Returns:
            Dictionary with generated code
        """
        if not self.api_key:
            return {
                "success": False,
                "error": "API key not configured"
            }
        
        prompt = f"""Generate {language} code based on this description:
"{description}"

Requirements:
1. Clean, readable code
2. Proper comments
3. Error handling where appropriate
4. Follow {language} best practices

Provide only the code, no explanation."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [
                            {"role": "system", "content": f"You are an expert {language} programmer. Generate clean, efficient code."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 2000,
                        "temperature": 0.7,
                    },
                    timeout=30.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    code = data["choices"][0]["message"]["content"]
                    # Extract code from markdown code block
                    if "```" in code:
                        code = code.split("```")[1]
                        if code.startswith(language):
                            code = code[len(language):]
                        code = code.strip()
                    return {
                        "success": True,
                        "code": code
                    }
                else:
                    return {
                        "success": False,
                        "error": f"API error: {response.status_code}"
                    }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
