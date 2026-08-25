from typing import TypedDict
from langgraph.graph import StateGraph, START, END

from app.security_rules import scan_code
from app.retrieval import HybridRetriever
from app.llm import LLMService


class ReviewState(TypedDict):
    code: str
    file_path: str
    deterministic: list
    policies: list
    response: str


class DevGuardWorkflow:

    def __init__(self):
        self.retriever = HybridRetriever()
        self.llm = LLMService(provider="ollama")

        workflow = StateGraph(ReviewState)

        workflow.add_node("security_scan", self.security_scan)
        workflow.add_node("retrieve", self.retrieve)
        workflow.add_node("reason", self.reason)

        workflow.add_edge(START, "security_scan")
        workflow.add_edge("security_scan", "retrieve")
        workflow.add_edge("retrieve", "reason")
        workflow.add_edge("reason", END)

        self.graph = workflow.compile()

    def security_scan(self, state: ReviewState):
        findings = scan_code(
            state.get("code", ""),
            state.get("file_path", "unknown")
        )
        return {"deterministic": findings}

    def retrieve(self, state: ReviewState):
        results = self.retriever.search(state.get("code", ""))
        return {"policies": results}

    def reason(self, state: ReviewState):
        policies = [p["text"] for p in state.get("policies", [])]
        answer = self.llm.analyze(
            state.get("code", ""),
            policies,
            state.get("deterministic", [])
        )
        return {"response": answer}

    def invoke(self, code: str, file_path: str):
        return self.graph.invoke({
            "code": code,
            "file_path": file_path
        })