"""LangGraph workflow definition."""

from __future__ import annotations

from langgraph.constants import Send
from langgraph.graph import END, START, StateGraph

from app.graph.nodes.aggregator import aggregator_node
from app.graph.nodes.attachment_agent import attachment_agent_node
from app.graph.nodes.explanation_agent import explanation_agent_node
from app.graph.nodes.message_agent import message_agent_node
from app.graph.nodes.planner import planner_node
from app.graph.nodes.risk_engine import risk_engine_node
from app.graph.nodes.url_agent import url_agent_node
from app.graph.state import InvestigationState


def _dispatch_agents(state: InvestigationState):
    # Fan out to all three agent nodes; each no-ops when its planner flag is false.
    return [
        Send("message_agent", state),
        Send("url_agent", state),
        Send("attachment_agent", state),
    ]


def build_workflow():
    graph = StateGraph(InvestigationState)

    graph.add_node("planner", planner_node)
    graph.add_node("message_agent", message_agent_node)
    graph.add_node("url_agent", url_agent_node)
    graph.add_node("attachment_agent", attachment_agent_node)
    graph.add_node("aggregator", aggregator_node)
    graph.add_node("risk_engine", risk_engine_node)
    graph.add_node("explanation_agent", explanation_agent_node)

    graph.add_edge(START, "planner")
    graph.add_conditional_edges(
        "planner",
        _dispatch_agents,
        ["message_agent", "url_agent", "attachment_agent"],
    )
    graph.add_edge(["message_agent", "url_agent", "attachment_agent"], "aggregator")
    graph.add_edge("aggregator", "risk_engine")
    graph.add_edge("risk_engine", "explanation_agent")
    graph.add_edge("explanation_agent", END)

    return graph.compile()


workflow = build_workflow()
