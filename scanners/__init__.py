"""
Pluggable scanner modules.

Each module exposes a ``run(...)`` function that performs one class of checks and
returns a list of findings in the application's common schema:

    {
        "status": "in-progress",
        "data": {
            "title": str,
            "severity": "high" | "medium" | "low" | "info",
            "description": str,
            "recommendation": str,
            "affected_components": [str, ...],
            "references": [str, ...],
            "type": str,          # module tag, e.g. "JWT"
        },
    }

Findings in this shape flow unchanged into the dashboard, tracker, AI enrichment
and SysReptor export.
"""
