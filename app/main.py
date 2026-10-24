
import math
import os
import re
import logging
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# --------------------------------------------------
# Application configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai-devops-detective")

app = FastAPI(
    title="AI DevOps Detective",
    version="1.1.0",
    description=(
        "Kubernetes troubleshooting and cost optimization "
        "with optional OpenRouter AI explanations."
    ),
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)


# --------------------------------------------------
# Request models
# --------------------------------------------------

class TroubleshootRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=20000)


class CostRequest(BaseModel):
    workloads: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=100,
    )


# --------------------------------------------------
# Sample data - dashboard is still in demo mode
# --------------------------------------------------

SAMPLE_WORKLOADS = [
    {
        "name": "frontend",
        "cpu_request_m": 500,
        "cpu_used_m": 90,
        "memory_request_mib": 512,
        "memory_used_mib": 180,
        "monthly_cost_usd": 24,
    },
    {
        "name": "api",
        "cpu_request_m": 1000,
        "cpu_used_m": 760,
        "memory_request_mib": 1024,
        "memory_used_mib": 850,
        "monthly_cost_usd": 58,
    },
    {
        "name": "worker-idle",
        "cpu_request_m": 800,
        "cpu_used_m": 35,
        "memory_request_mib": 1024,
        "memory_used_mib": 140,
        "monthly_cost_usd": 42,
    },
]


# --------------------------------------------------
# Rule-based Kubernetes diagnosis
# --------------------------------------------------

def rule_based_diagnosis(logs: str) -> dict:
    lower = logs.lower()
    findings = []

    if (
        "crashloopbackoff" in lower
        or "back-off restarting" in lower
    ):
        findings.append({
            "issue": "Container repeatedly exits",
            "likely_cause": (
                "The process may be crashing, exiting with an "
                "error, or failing its startup configuration."
            ),
            "checks": [
                "Run kubectl logs <pod> --previous",
                "Run kubectl describe pod <pod>",
                (
                    "Check the container command, environment "
                    "variables, and startup dependencies."
                ),
            ],
            "severity": "high",
        })

    if (
        "imagepullbackoff" in lower
        or "errimagepull" in lower
    ):
        findings.append({
            "issue": "Container image cannot be pulled",
            "likely_cause": (
                "The image name/tag may be wrong, the registry "
                "may be unavailable, or image pull credentials "
                "may be missing."
            ),
            "checks": [
                "Run kubectl describe pod <pod>",
                "Verify image repository and tag",
                "Check registry access and imagePullSecrets",
            ],
            "severity": "high",
        })

    if (
        "failedscheduling" in lower
        or "insufficient cpu" in lower
        or "insufficient memory" in lower
        or re.search(
            r"status:\s*pending|\s0/\d+\s+pending\s",
            lower,
        )
    ):
        findings.append({
            "issue": "Pod cannot be scheduled",
            "likely_cause": (
                "The cluster may lack requested CPU/memory "
                "capacity, or node selectors and taints may "
                "prevent scheduling."
            ),
            "checks": [
                "Run kubectl describe pod <pod>",
                "Run kubectl get nodes",
                (
                    "Review requests, limits, node selectors, "
                    "taints, and tolerations."
                ),
            ],
            "severity": "medium",
        })

    if (
        "oomkilled" in lower
        or "out of memory" in lower
    ):
        findings.append({
            "issue": "Container ran out of memory",
            "likely_cause": (
                "The process exceeded its memory limit or "
                "may have a memory leak."
            ),
            "checks": [
                "Review container memory usage and limits",
                "Inspect application logs",
                (
                    "Tune memory requests/limits based on "
                    "observed usage."
                ),
            ],
            "severity": "high",
        })

    if (
        "readiness probe failed" in lower
        or "liveness probe failed" in lower
    ):
        findings.append({
            "issue": "Health probe is failing",
            "likely_cause": (
                "The health endpoint may be unavailable, slow, "
                "misconfigured, or unreachable from the probe."
            ),
            "checks": [
                "Run kubectl describe pod <pod>",
                (
                    "Verify probe path, port, scheme, "
                    "and timing."
                ),
                (
                    "Check application startup time and "
                    "health endpoint."
                ),
            ],
            "severity": "medium",
        })

    if not findings:
        findings.append({
            "issue": "No known signature matched",
            "likely_cause": (
                "The supplied text does not match the starter "
                "rules. More context may be needed."
            ),
            "checks": [
                "Include kubectl describe pod output and recent logs",
                (
                    "Check Kubernetes events with "
                    "kubectl get events "
                    "--sort-by=.metadata.creationTimestamp"
                ),
                "Redact secrets before sharing logs with an AI provider",
            ],
            "severity": "info",
        })

    return {
        "summary": (
            f"Found {len(findings)} potential issue(s). "
            "Treat these as hypotheses, not confirmed root causes."
        ),
        "findings": findings,
        "source": "rules",
    }


# --------------------------------------------------
# Secret redaction before sending logs to the AI provider
# --------------------------------------------------

_SECRET_PATTERNS = [
    (
        re.compile(
            r"(?i)(authorization:\s*bearer\s+)[^\s]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key)"
            r"\b(\s*[=:]\s*)[^\s,;]+"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            r"\b(sk-[A-Za-z0-9_-]{16,}|"
            r"ghp_[A-Za-z0-9]{20,}|"
            r"AKIA[0-9A-Z]{16})\b"
        ),
        "[REDACTED]",
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)

    return text


# --------------------------------------------------
# Optional OpenRouter AI explanation
# --------------------------------------------------

def optional_ai_explanation(logs: str, base: dict) -> dict:
    api_key = os.getenv(
        "OPENROUTER_API_KEY", ""
    ).strip()

    if not api_key:
        return {
            **base,
            "ai_explanation": None,
            "ai_note": (
                "OPENROUTER_API_KEY is missing from "
                "the running service."
            ),
        }

    model = os.getenv(
        "OPENROUTER_MODEL",
        "openrouter/free",
    ).strip()

    prompt = (
        "You are a cautious DevOps assistant. Analyze the "
        "redacted Kubernetes log excerpt. Return concise plain "
        "text covering likely cause, evidence, safe diagnostic "
        "checks, and remediation cautions. Treat causes as "
        "hypotheses. Do not execute commands or request secrets.\n\n"
        f"Rule-based findings: {base}\n"
        f"Log excerpt:\n{redact(logs)[:12000]}"
    )

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": (
                    "https://github.com/darshem-21/"
                    "ai-devops-detective"
                ),
                "X-Title": "AI DevOps Detective",
            },
            json={
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                "temperature": 0.2,
            },
            timeout=25,
        )

        if not response.ok:
            # Do not log API keys, headers, or raw request data.
            logger.warning(
                "OpenRouter request failed with HTTP %s",
                response.status_code,
            )

            return {
                **base,
                "ai_explanation": None,
                "ai_note": (
                    f"OpenRouter returned HTTP "
                    f"{response.status_code}."
                ),
            }

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        if not isinstance(content, str) or not content.strip():
            return {
                **base,
                "ai_explanation": None,
                "ai_note": (
                    "OpenRouter returned an empty AI response."
                ),
            }

        logger.info("OpenRouter AI explanation succeeded")

        return {
            **base,
            "ai_explanation": content.strip(),
            "source": "rules+ai",
        }

    except requests.Timeout:
        logger.warning("OpenRouter request timed out")

        return {
            **base,
            "ai_explanation": None,
            "ai_note": (
                "OpenRouter request timed out after 25 seconds."
            ),
        }

    except requests.RequestException as exc:
        # Log the exception class, not potentially sensitive request details.
        logger.warning(
            "OpenRouter network error: %s",
            type(exc).__name__,
        )

        return {
            **base,
            "ai_explanation": None,
            "ai_note": (
                "OpenRouter network request failed: "
                f"{type(exc).__name__}."
            ),
        }

    except (ValueError, KeyError, TypeError):
        logger.warning(
            "OpenRouter returned an unexpected response format"
        )

        return {
            **base,
            "ai_explanation": None,
            "ai_note": (
                "OpenRouter returned an unexpected response format."
            ),
        }


# --------------------------------------------------
# Cost analysis
# --------------------------------------------------

def analyze_costs(workloads: list[dict[str, Any]]) -> dict:
    results = []
    total_cost = 0.0
    estimated_savings = 0.0

    for index, workload in enumerate(workloads):
        try:
            name = str(
                workload.get(
                    "name",
                    f"workload-{index + 1}",
                )
            )[:100]

            cpu_req = max(
                float(workload["cpu_request_m"]), 0
            )
            cpu_used = max(
                float(workload["cpu_used_m"]), 0
            )
            mem_req = max(
                float(workload["memory_request_mib"]), 0
            )
            mem_used = max(
                float(workload["memory_used_mib"]), 0
            )
            monthly_cost = max(
                float(workload.get("monthly_cost_usd", 0)),
                0,
            )

            if not all(
                math.isfinite(value)
                for value in (
                    cpu_req,
                    cpu_used,
                    mem_req,
                    mem_used,
                    monthly_cost,
                )
            ):
                raise ValueError("Non-finite number")

        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=422,
                detail=(
                    "Each workload needs numeric CPU and memory "
                    "request/usage fields."
                ),
            )

        cpu_ratio = (
            cpu_used / cpu_req if cpu_req else None
        )
        mem_ratio = (
            mem_used / mem_req if mem_req else None
        )

        flags = []

        if cpu_req > 0 and cpu_ratio < 0.25:
            flags.append(
                "CPU request is much higher than observed usage"
            )

        if mem_req > 0 and mem_ratio < 0.35:
            flags.append(
                "Memory request may be oversized; "
                "check peak usage before changing it"
            )

        # Illustrative estimate only.
        savings = (
            monthly_cost * 0.20
            if len(flags) == 2
            else 0.0
        )

        total_cost += monthly_cost
        estimated_savings += savings

        results.append({
            "name": name,
            "cpu_utilization_pct": (
                round(cpu_ratio * 100, 1)
                if cpu_ratio is not None
                else None
            ),
            "memory_utilization_pct": (
                round(mem_ratio * 100, 1)
                if mem_ratio is not None
                else None
            ),
            "monthly_cost_usd": round(monthly_cost, 2),
            "estimated_savings_usd": round(savings, 2),
            "flags": flags,
        })

    return {
        "workloads": results,
        "total_monthly_cost_usd": round(total_cost, 2),
        "illustrative_monthly_savings_usd": round(
            estimated_savings, 2
        ),
        "note": (
            "Illustrative estimate only, not a cloud bill or "
            "guaranteed savings. Validate peak load, replicas, "
            "autoscaling, and provider pricing before changes."
        ),
    }


# --------------------------------------------------
# API endpoints
# --------------------------------------------------

@app.get("/")
def index():
    return FileResponse(
        BASE_DIR / "static" / "index.html"
    )


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ai-devops-detective",
    }


@app.get("/api/overview")
def overview():
    costs = analyze_costs(SAMPLE_WORKLOADS)

    return {
        "cluster": {
            "status": "DEMO MODE",
            "nodes": 3,
            "pods": 18,
            "incidents": 2,
        },
        "costs": costs,
        "sample_workloads": SAMPLE_WORKLOADS,
        "notice": (
            "Sample data only. No live Kubernetes "
            "cluster is connected."
        ),
    }


@app.post("/api/troubleshoot")
def troubleshoot(payload: TroubleshootRequest):
    result = rule_based_diagnosis(payload.logs)

    return optional_ai_explanation(
        payload.logs,
        result,
    )


@app.post("/api/costs")
def costs(payload: CostRequest):
    return analyze_costs(payload.workloads)
