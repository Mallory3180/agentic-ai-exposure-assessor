"""Example: instrument a *live* LangGraph app so its traces flow to the assessor.

This is a template you adapt to one of the GenAI Agent Security Initiative LangGraph
samples (e.g. unrestricted_agent / Excessive Db Agency / multi_agent). It does NOT run any
attack — it simply turns on OpenTelemetry tracing and then invokes the graph you built, so
the assessor can observe the tool calls.

Prerequisites:
    python -m pip install -e ".[langgraph]"
    # plus the sample's own deps (langgraph, langchain, the model SDK, etc.)

Run the assessor's receiver first (separate terminal):
    python -m agentic_ai_exposure_assessor.cli serve
    # OTLP/HTTP receiver: http://127.0.0.1:8000/v1/traces

Then run this file, and finally:
    python -m agentic_ai_exposure_assessor.cli assess
    python -m agentic_ai_exposure_assessor.cli export-report \
        --format html --output ./reports/report.html
"""

from __future__ import annotations

from agentic_ai_exposure_assessor.integrations import langgraph as lg


def main() -> None:
    # 1) Turn on tracing -> export OTLP to the assessor's receiver.
    lg.instrument_langgraph(
        endpoint="http://127.0.0.1:8000/v1/traces",
        service_name="unrestricted-bash-agent",  # becomes agent.name in the assessment
    )

    # 2) Build the LangGraph app from the sample you are assessing. For example, adapt
    #    code_samples/.../langgraph/unrestricted_agent/agent.py to expose a compiled graph:
    #
    #    from my_sample import build_graph
    #    app = build_graph()
    #    app.invoke({"messages": ["show me the current directory"]})
    #
    # Every LLM/tool/chain step is captured as an OpenInference span and streamed to the
    # assessor. The assessor maps tool.name / input.value / langgraph.node automatically.
    raise SystemExit(
        "Edit langgraph_runner.py: import and invoke the LangGraph sample you want to assess."
    )


if __name__ == "__main__":
    main()
