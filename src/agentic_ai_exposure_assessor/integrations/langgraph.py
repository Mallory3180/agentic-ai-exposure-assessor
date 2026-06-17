"""LangGraph / LangChain instrumentation helper.

Turns a *running* LangGraph (or any LangChain) app into a live trace source for the
assessor: it wires up OpenTelemetry + OpenInference LangChain instrumentation and exports
spans (OTLP/HTTP, JSON) to the assessor's ``/v1/traces`` receiver. The assessor already
understands OpenInference span attributes (``openinference.span.kind``, ``tool.name``,
``input.value``, ``langgraph.node`` ...), so no extra mapping is needed.

Dependencies are optional and imported lazily::

    python -m pip install -e ".[langgraph]"

Usage::

    from agentic_ai_exposure_assessor.integrations import langgraph as lg
    lg.instrument_langgraph(endpoint="http://127.0.0.1:8000/v1/traces",
                            service_name="my-langgraph-agent")
    # ... build and run your LangGraph app as usual; spans stream to the assessor ...

This module never sends prompts itself; it only observes the app you run.
"""

from __future__ import annotations

DEFAULT_ENDPOINT = "http://127.0.0.1:8000/v1/traces"

_MISSING_DEPS_HINT = (
    "LangGraph instrumentation requires optional dependencies. Install them with:\n"
    '    python -m pip install -e ".[langgraph]"\n'
    "(opentelemetry-sdk, opentelemetry-exporter-otlp-proto-http, "
    "openinference-instrumentation-langchain)"
)


class InstrumentationError(RuntimeError):
    """Raised when instrumentation cannot be set up."""


def instrument_langgraph(
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    service_name: str = "langgraph-agent",
    headers: dict[str, str] | None = None,
) -> object:
    """Configure OpenTelemetry tracing + OpenInference LangChain instrumentation.

    Returns the configured ``TracerProvider``. Call once before running your graph.
    ``endpoint`` should be the assessor's OTLP/HTTP traces endpoint.
    """
    try:
        from openinference.instrumentation.langchain import LangChainInstrumentor
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:  # pragma: no cover - exercised only without extras
        raise InstrumentationError(_MISSING_DEPS_HINT) from exc

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint, headers=headers or {})
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    LangChainInstrumentor().instrument(tracer_provider=provider)
    return provider
