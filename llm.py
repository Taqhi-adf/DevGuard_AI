import json

from langchain_ollama import ChatOllama
from langchain_groq import ChatGroq

from app.config import settings


SYSTEM_PROMPT = """
You are DevGuard AI.

You are an enterprise software security reviewer.

Analyze the supplied code and security policies.

Rules:

1. Never invent vulnerabilities.
2. Use evidence from the code.
3. Explain why the issue matters.
4. Give actionable remediation.
5. Prefer conservative findings.
6. Return valid JSON.
"""


class LLMService:

    def __init__(
        self,
        provider="ollama"
    ):

        self.provider = provider

        if provider == "ollama":

            self.llm = ChatOllama(

                model=
                    settings.ollama_model,

                base_url=
                    settings.ollama_base_url,

                temperature=0

            )

        else:

            self.llm = ChatGroq(

                model=
                    settings.groq_model,

                temperature=0,

                api_key=
                    settings.groq_api_key

            )

    def analyze(
        self,
        code,
        policies,
        deterministic_findings
    ):

        prompt = f"""

{SYSTEM_PROMPT}

CODE:

{code}

SECURITY POLICIES:

{policies}

DETERMINISTIC FINDINGS:

{json.dumps(
    deterministic_findings,
    indent=2
)}

Return:

{{
    "summary": "...",
    "overall_score": 0,
    "risk_level": "...",
    "findings": []
}}

"""

        response = self.llm.invoke(
            prompt
        )

        return response.content