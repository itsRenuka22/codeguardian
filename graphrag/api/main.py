"""
CodeGuardian API

Run from graphrag/ directory:
    uvicorn api.main:app --reload --port 8000
"""
import os
import sys
import json
import uuid
from typing import Optional, Dict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

# Load environment variables from .env file (located in parent directory)
_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(_ENV_PATH)

_HERE     = os.path.dirname(os.path.abspath(__file__))
_GRAPHRAG = os.path.dirname(_HERE)
sys.path.insert(0, _GRAPHRAG)
sys.path.insert(0, os.path.join(_GRAPHRAG, "src"))
sys.path.insert(0, os.path.join(_GRAPHRAG, "models"))

app  = FastAPI(title="CodeGuardian", version="1.0.0")
_pool = ThreadPoolExecutor(max_workers=2)

# ── Agent (lazy) ──────────────────────────────────────────────
_agent = None
_agent_error: Optional[str] = None


def _get_agent():
    global _agent, _agent_error
    if _agent is not None:
        return _agent
    if _agent_error:
        raise RuntimeError(_agent_error)
    try:
        import config
        from agent.agent import CodeGuardianAgent
        _agent = CodeGuardianAgent.from_config(config)
    except Exception as exc:
        _agent_error = str(exc)
        raise RuntimeError(_agent_error) from exc
    return _agent


# ── Analysis session store (1-hour TTL) ──────────────────────
_analysis_sessions: Dict[str, dict] = {}

def _cleanup_sessions():
    """Remove sessions older than 1 hour"""
    cutoff = datetime.now() - timedelta(hours=1)
    expired = [sid for sid, data in _analysis_sessions.items() if data.get("timestamp", datetime.now()) < cutoff]
    for sid in expired:
        del _analysis_sessions[sid]

# ── Runtime API key store ──────────────────────────────────────
_api_keys: dict = {}

# Ollama model registry (models actually pulled locally)
_OLLAMA_MODELS = {
    "deepseek-r1": "deepseek-r1:8b",
    "gemma3-1b":   "gemma2:2b",
}

# Cloud model display names for /api/models
_CLOUD_MODELS = [
    ("gemini-flash", "GeminiClient"),
]


def _make_llm(model_key: str, api_key: str = ""):
    from models.ollama_client  import OllamaClient
    from models.gemini_client  import GeminiClient

    key = api_key or _api_keys.get(model_key, "")

    if model_key == "gemini-flash": return GeminiClient(api_key=key)
    if model_key in _OLLAMA_MODELS:
        return OllamaClient(model=_OLLAMA_MODELS[model_key])
    raise ValueError(f"Unknown model key: {model_key!r}")


_STATIC = os.path.join(_GRAPHRAG, "static")

# ── Routes ────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(os.path.join(_STATIC, "index.html"))


@app.post("/api/analyze")
async def analyze(request: Request):
    body      = await request.json()
    code      = body.get("code", "").strip()
    model_key = body.get("model", "").strip()
    api_key   = body.get("api_key", "").strip()

    if not code:
        raise HTTPException(400, "No code provided")

    try:
        result = _get_agent().analyze(code)
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc

    if model_key:
        try:
            llm = _make_llm(model_key, api_key)
            if not llm.is_available:
                result["report"]       = None
                result["report_error"] = f"{llm.display_name} — API key not configured"
            else:
                report_data = llm.generate_report(result, code)
                result["report"]        = report_data["text"]
                result["report_model"]  = llm.display_name
                result["report_usage"]  = {
                    "input_tokens":  report_data["input_tokens"],
                    "output_tokens": report_data["output_tokens"],
                    "cost_usd":      report_data["cost_usd"],
                }
        except Exception as exc:
            result["report"]       = None
            result["report_error"] = str(exc)

    return JSONResponse(result)


@app.post("/api/analyze-quick")
async def analyze_quick(request: Request):
    """Fast GraphRAG analysis without LLM report (~5 seconds)"""
    _cleanup_sessions()

    body      = await request.json()
    code      = body.get("code", "").strip()
    model_key = body.get("model", "").strip()

    if not code:
        raise HTTPException(400, "No code provided")

    try:
        result = _get_agent().analyze(code)
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc

    # Generate analysis ID and store session
    analysis_id = str(uuid.uuid4())
    _analysis_sessions[analysis_id] = {
        "code": code,
        "result": result,
        "model": model_key,
        "timestamp": datetime.now(),
    }

    return JSONResponse({
        "analysis_id": analysis_id,
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "vulnerability_types": result.get("vulnerability_types", []),
        "vulnerabilities": result.get("vulnerabilities", []),
        "evidence": result.get("evidence", []),
        "fix_guidance": result.get("fix_guidance", []),
    })


@app.post("/api/generate-report-stream")
async def generate_report_stream(request: Request):
    """Generate LLM report on demand for stored analysis"""
    body        = await request.json()
    analysis_id = body.get("analysis_id", "").strip()
    api_key     = body.get("api_key", "").strip()

    # Retrieve stored analysis
    session = _analysis_sessions.get(analysis_id)
    if not session:
        raise HTTPException(404, "Analysis session not found or expired")

    model_key = session.get("model", "gemini-flash")
    code = session["code"]
    result = session["result"]

    async def event_generator():
        import socket
        import urllib.error

        try:
            # Get LLM client
            llm = _make_llm(model_key, api_key or _api_keys.get(model_key, ""))

            if not llm.is_available:
                yield f"data: {json.dumps({'type': 'error', 'message': f'{llm.display_name} — API key not configured'})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'start', 'model': llm.display_name})}\n\n"

            # Generate report
            try:
                report_data = llm.generate_report(result, code)
            except (socket.timeout, urllib.error.URLError) as e:
                timeout_val = getattr(llm, "_TIMEOUT_S", "unknown")
                msg = f"{llm.display_name} timed out after {timeout_val}s"
                yield f"data: {json.dumps({'type': 'error', 'message': msg})}\n\n"
                return
            except Exception as e:
                msg = f"{llm.display_name} error: {str(e)}"
                yield f"data: {json.dumps({'type': 'error', 'message': msg})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'report', 'content': report_data['text']})}\n\n"
            yield f"data: {json.dumps({'type': 'metadata', 'tokens_in': report_data['input_tokens'], 'tokens_out': report_data['output_tokens'], 'cost': report_data['cost_usd']})}\n\n"
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/analyze-stream")
async def analyze_stream(request: Request):
    """Streaming analysis with real-time agent progress visibility"""
    _cleanup_sessions()

    body      = await request.json()
    code      = body.get("code", "").strip()
    model_key = body.get("model", "").strip()

    if not code:
        raise HTTPException(400, "No code provided")

    async def event_generator():
        try:
            agent = _get_agent()

            # ── PLANNER ────────────────────────────────────────────
            yield f"data: {json.dumps({'type': 'progress', 'step': 'planning', 'message': '🎯 PLANNER: Analyzing code structure…'})}\n\n"

            plan = agent.planner.plan(code)

            yield f"data: {json.dumps({'type': 'detail', 'step': 'planning', 'message': f'→ Language detected: {plan.language.upper()}'})}\n\n"
            if plan.suspected_vulns:
                vuln_list = ', '.join(plan.suspected_vulns)
                yield f"data: {json.dumps({'type': 'detail', 'step': 'planning', 'message': f'→ Suspected: {vuln_list}'})}\n\n"
            yield f"data: {json.dumps({'type': 'detail', 'step': 'planning', 'message': f'→ Building {len(plan.queries)} search queries'})}\n\n"

            # ── EXECUTOR ───────────────────────────────────────────
            yield f"data: {json.dumps({'type': 'progress', 'step': 'searching', 'message': f'⚙️ EXECUTOR: Running {len(plan.queries)} queries in parallel…'})}\n\n"
            yield f"data: {json.dumps({'type': 'detail', 'step': 'searching', 'message': '→ Knowledge base: 260 examples across 12 vulnerability types'})}\n\n"

            exec_result = agent.executor.execute(plan)
            matches = exec_result.matches
            top_dist = min((m.get("similarity_distance", 1.0) for m in matches), default=1.0)

            sim_label = (
                "very similar"       if top_dist < 0.30 else
                "moderately similar" if top_dist < 0.45 else
                "weakly similar"
            )
            yield f"data: {json.dumps({'type': 'detail', 'step': 'searching', 'message': f'→ {len(matches)} unique matches retrieved'})}\n\n"
            if matches:
                yield f"data: {json.dumps({'type': 'detail', 'step': 'searching', 'message': f'→ Top match: distance {top_dist:.3f} ({sim_label})'})}\n\n"

            # ── CRITIC ─────────────────────────────────────────────
            yield f"data: {json.dumps({'type': 'progress', 'step': 'scoring', 'message': '🧠 CRITIC: Evaluating results…'})}\n\n"
            yield f"data: {json.dumps({'type': 'detail', 'step': 'scoring', 'message': '→ Running semantic validation…'})}\n\n"

            score = agent.critic.score(code, exec_result)

            yield f"data: {json.dumps({'type': 'detail', 'step': 'scoring', 'message': f'→ Verdict: {score.verdict.upper()}'})}\n\n"
            yield f"data: {json.dumps({'type': 'detail', 'step': 'scoring', 'message': f'→ Confidence: {score.confidence*100:.0f}%'})}\n\n"

            # ── STORE SESSION & RETURN RESULTS ──────────────────────
            analysis_id = str(uuid.uuid4())
            _analysis_sessions[analysis_id] = {
                "code": code,
                "result": agent._format(code, plan, exec_result, score, 1),
                "model": model_key,
                "timestamp": datetime.now(),
            }

            result = agent._format(code, plan, exec_result, score, 1)
            yield f"data: {json.dumps({'type': 'complete', 'analysis_id': analysis_id, 'verdict': score.verdict, 'confidence': score.confidence})}\n\n"

        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/models")
async def list_models():
    from models.gemini_client  import GeminiClient
    from models.ollama_client  import OllamaClient

    # Check Ollama once
    try:
        ollama_up = OllamaClient().is_available
    except Exception:
        ollama_up = False

    out = []

    # Cloud models (Gemini only)
    for key, Cls in [("gemini-flash", GeminiClient)]:
        k = _api_keys.get(key, "")
        try:
            inst  = Cls(api_key=k)
            avail = inst.is_available
        except Exception:
            avail = False
        out.append({
            "key":       key,
            "name":      Cls.display_name,
            "available": avail,
            "needs_key": True,
            "has_key":   bool(k),
            "category":  "cloud",
        })

    # Ollama models
    for key, ollama_model in _OLLAMA_MODELS.items():
        try:
            inst = OllamaClient(model=ollama_model)
            name = inst.display_name
        except Exception:
            name = ollama_model
        out.append({
            "key":       key,
            "name":      name,
            "available": ollama_up,
            "needs_key": False,
            "has_key":   True,
            "category":  "ollama",
        })

    return out


@app.post("/api/models/configure")
async def configure_model(request: Request):
    body  = await request.json()
    model = body.get("model", "")
    key   = body.get("api_key", "").strip()
    if model not in ("gemini-flash",):
        raise HTTPException(400, f"Unknown cloud model: {model!r}")
    _api_keys[model] = key
    return {"status": "ok", "model": model}


@app.get("/api/cache-stats")
async def cache_stats():
    try:
        return _get_agent().memory_stats()
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@app.post("/api/clear-cache")
async def clear_cache():
    try:
        _get_agent().clear_cache()
        return {"status": "cleared"}
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


# ── Evaluation ────────────────────────────────────────────────

@app.get("/api/eval/results")
async def eval_results():
    import config
    path = os.path.join(os.path.dirname(config.__file__), "data", "eval_results.json")
    if not os.path.exists(path):
        raise HTTPException(404, "No results yet. POST /api/eval/run to generate them.")
    with open(path) as f:
        return json.load(f)


@app.post("/api/eval/run")
async def eval_run():
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_pool, _run_eval_sync)
    return result


def _run_eval_sync() -> dict:
    import config

    with open(config.EVALUATION_SET_PATH) as f:
        ev = json.load(f)
    cases = ev.get("test_cases", [])
    agent = _get_agent()

    tp = fp = tn = fn = 0
    cases_log = []

    for case in cases:
        gt       = case["ground_truth"]
        gt_vuln  = gt.get("vulnerable", True)
        gt_types = set(gt.get("vulnerability_types", []))

        r          = agent.analyze(case["code"])
        pred_vuln  = r["verdict"] in ("vulnerable", "likely_vulnerable")
        pred_types = set(r["vulnerability_types"])
        type_match = bool(gt_types & pred_types) if gt_types else True

        if gt_vuln and pred_vuln:       outcome = "TP"; tp += 1
        elif gt_vuln and not pred_vuln: outcome = "FN"; fn += 1
        elif pred_vuln:                 outcome = "FP"; fp += 1
        else:                           outcome = "TN"; tn += 1

        cases_log.append({
            "test_id":     case["test_id"],
            "outcome":     outcome,
            "confidence":  round(r["confidence"], 3),
            "gt_verdict":  gt_vuln,
            "pred_verdict": pred_vuln,
            "gt_vulns":    list(gt_types),
            "pred_vulns":  list(pred_types),
            "vuln_match":  type_match,
            "iterations":  r.get("iterations", 1),
        })

    def _d(a, b): return round(a / b, 4) if b else 0.0

    prec   = _d(tp, tp + fp)
    rec    = _d(tp, tp + fn)
    f1     = _d(2 * prec * rec, prec + rec)
    acc    = _d(tp + tn, len(cases))
    gt_p   = sum(1 for r in cases_log if r["gt_verdict"])
    vt_acc = _d(sum(1 for r in cases_log if r["vuln_match"] and r["gt_verdict"]), gt_p)

    graphrag_metrics = {
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "vuln_type_accuracy": vt_acc,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": len(cases),
    }

    vo_metrics = _vector_only_eval(cases, agent)

    out = {"metrics": graphrag_metrics, "vector_only": vo_metrics, "cases": cases_log}

    path = os.path.join(os.path.dirname(config.__file__), "data", "eval_results.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)

    return out


def _vector_only_eval(cases: list, agent) -> dict:
    tp = fp = tn = fn = vm = gt_pos = 0
    querier = agent.executor.querier

    for case in cases:
        gt       = case["ground_truth"]
        gt_vuln  = gt.get("vulnerable", True)
        gt_types = set(gt.get("vulnerability_types", []))
        if gt_vuln:
            gt_pos += 1

        hits = querier.vector_search(case["code"][:500], top_k=5)
        if not hits:
            pred_vuln  = False
            type_match = False
        else:
            pred_vuln  = hits[0]["distance"] < 0.55
            pred_types = set()
            col = querier._collection_obj()
            if col and hits:
                try:
                    meta = col.get(ids=[h["id"] for h in hits[:3]], include=["metadatas"])
                    for m in meta.get("metadatas", []):
                        raw = m.get("vulnerability_types", "")
                        pred_types.update(t.strip() for t in raw.split(",") if t.strip())
                except Exception:
                    pass
            type_match = bool(gt_types & pred_types) if gt_types else True

        if gt_vuln and pred_vuln:       tp += 1
        elif gt_vuln and not pred_vuln: fn += 1
        elif pred_vuln:                 fp += 1
        else:                           tn += 1

        if gt_vuln and type_match:
            vm += 1

    def _d(a, b): return round(a / b, 4) if b else 0.0
    prec = _d(tp, tp + fp)
    rec  = _d(tp, tp + fn)
    return {
        "accuracy":           _d(tp + tn, len(cases)),
        "precision":          prec,
        "recall":             rec,
        "f1":                 _d(2 * prec * rec, prec + rec),
        "vuln_type_accuracy": _d(vm, gt_pos),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": len(cases),
    }


@app.post("/api/eval/models")
async def eval_models(request: Request):
    import asyncio
    body      = await request.json()
    models    = body.get("models", [])
    max_cases = min(int(body.get("max_cases", 10)), 65)
    keys_in   = body.get("api_keys", {})

    for k, v in keys_in.items():
        if v:
            _api_keys[k] = v

    if not models:
        raise HTTPException(400, "No models selected")

    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(_pool, _run_model_eval_sync, models, max_cases)
    return JSONResponse(result)


def _run_model_eval_sync(model_keys: list, max_cases: int) -> dict:
    from models.llm_evaluator import LLMEvaluator
    import config

    with open(config.EVALUATION_SET_PATH) as f:
        ev = json.load(f)
    cases = ev.get("test_cases", [])[:max_cases]

    evaluator      = LLMEvaluator()
    results_by_model = {}

    for model_key in model_keys:
        try:
            llm = _make_llm(model_key)
        except Exception as exc:
            results_by_model[model_key] = {"error": str(exc)}
            continue

        if not llm.is_available:
            results_by_model[model_key] = {
                "model_name": llm.display_name,
                "error": f"{llm.display_name} — API key not configured or service unavailable",
            }
            continue

        tp = fp = tn = fn = 0
        total_cost    = 0.0
        total_latency = 0.0
        vuln_matches  = 0
        gt_pos        = 0
        cases_log     = []

        for case in cases:
            gt       = case["ground_truth"]
            gt_vuln  = gt.get("vulnerable", True)
            gt_types = set(gt.get("vulnerability_types", []))
            if gt_vuln:
                gt_pos += 1

            try:
                r          = evaluator.evaluate_case(case["code"], llm)
                pred_vuln  = r["verdict"] in ("vulnerable", "likely_vulnerable")
                pred_types = set(r["vulnerability_types"])
                type_match = bool(gt_types & pred_types) if gt_types else True

                if gt_vuln and pred_vuln:       tp += 1
                elif gt_vuln and not pred_vuln: fn += 1
                elif pred_vuln:                 fp += 1
                else:                           tn += 1

                if gt_vuln and type_match:
                    vuln_matches += 1

                total_cost    += r["cost_usd"]
                total_latency += r["latency_s"]

                outcome = (
                    "TP" if (gt_vuln and pred_vuln) else
                    "FN" if (gt_vuln and not pred_vuln) else
                    "FP" if pred_vuln else "TN"
                )
                cases_log.append({
                    "test_id":    case["test_id"],
                    "outcome":    outcome,
                    "gt_verdict": gt_vuln,
                    "pred_verdict": pred_vuln,
                    "gt_vulns":   list(gt_types),
                    "pred_vulns": list(pred_types),
                    "type_match": type_match,
                    "cost_usd":   round(r["cost_usd"], 6),
                    "latency_s":  r["latency_s"],
                    "reasoning":  r.get("reasoning", ""),
                })
            except TimeoutError as exc:
                cases_log.append({
                    "test_id": case.get("test_id", "?"),
                    "error":   f"TIMEOUT: {str(exc)}",
                    "error_type": "timeout",
                })
            except RuntimeError as exc:
                cases_log.append({
                    "test_id": case.get("test_id", "?"),
                    "error":   f"LLM_ERROR: {str(exc)}",
                    "error_type": "llm_error",
                })
            except Exception as exc:
                cases_log.append({
                    "test_id": case.get("test_id", "?"),
                    "error":   f"UNKNOWN: {str(exc)}",
                    "error_type": "unknown",
                })

        n = len(cases) or 1

        def _d(a, b): return round(a / b, 4) if b else 0.0
        prec = _d(tp, tp + fp)
        rec  = _d(tp, tp + fn)
        f1   = _d(2 * prec * rec, prec + rec)

        results_by_model[model_key] = {
            "model_name": llm.display_name,
            "metrics": {
                "accuracy":          _d(tp + tn, n),
                "precision":         prec,
                "recall":            rec,
                "f1":                f1,
                "vuln_type_accuracy": _d(vuln_matches, gt_pos),
                "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": len(cases),
            },
            "total_cost_usd":  round(total_cost, 4),
            "avg_latency_s":   round(total_latency / n, 2),
            "cases": cases_log,
        }

    return {"models": results_by_model, "num_cases": len(cases)}


@app.get("/api/health")
async def health():
    return {"status": "ok"}
