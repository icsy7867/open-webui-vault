"""
title: Secret Vault
author: open-webui-plugin
version: 6.2.0
description: >
  Per-user secret key/value store with password-masked UI.

  KEY TYPES:
    - LLM Secrets (LLM_SECRET_1 through LLM_SECRET_6):
      Resolved in chat messages and system prompts. The LLM sees the value.
      Use for: API keys or tokens the model needs to reference or pass along.
    - Tool Secrets (TOOL_SECRET_1 through TOOL_SECRET_6):
      NEVER resolved in chat. Only OW-UI Python Tool code can read the raw
      value via use_tool_secret(). Scrubbed from model responses.
      Use for: credentials used server-side in custom Python Tool code.

  NOTE ON MCP / OpenAPI SERVERS:
    MCP and OpenAPI server connection headers/env are handled by OW-UI at
    connection time -- not during chat requests. The Filter only runs on
    chat completion requests and cannot inject secrets into server connection
    config. Store those credentials directly in the server config, or protect
    servers at the network level (VPN, reverse proxy).

  SETUP:
    1. Install as TOOL   (Workspace -> Tools -> Add Tool)
    2. Install as FILTER (Admin -> Functions -> Add Function, enable, Global)
    3. Configure Filter Valves (gear icon on the Function):
         TOOL_ID       : from URL when editing tool: /workspace/tools/edit/<ID>
         OWUI_BASE_URL : e.g. http://localhost:3000  (only needed if Strategy 1 fails)
         OWUI_API_KEY  : API key                     (only needed if Strategy 1 fails)
    4. Each user sets secrets via wrench icon -> Secret Vault -> person icon

  USAGE:
    ${{{LLM_SECRET_1}}}  -> resolved in messages before the LLM sees them
    ${{{TOOL_SECRET_1}}} -> never resolved; OW-UI Python Tool code reads raw value

  CHANGELOG:
    6.2.0 - Fixed compatibility with OW-UI 0.8.6+ (Pydantic v2 model_dump support
            in _vault_from_obj). Scrubbing now applies to all secret types in outlet.

  REQUIRES: Open WebUI >= 0.6.x
license: MIT
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

try:
    from pydantic import BaseModel, Field  # type: ignore
except ImportError:
    class BaseModel:  # type: ignore
        pass
    def Field(*a, **kw):  # type: ignore
        return kw.get("default", None)


# ── token pattern ──────────────────────────────────────────────────────────────
_TOKEN_RE = re.compile(r"\$\{\{\{([A-Za-z0-9_]+)\}\}\}")

# ── key groups ─────────────────────────────────────────────────────────────────
_LLM_KEYS  = ["LLM_SECRET_1",  "LLM_SECRET_2",  "LLM_SECRET_3",
              "LLM_SECRET_4",  "LLM_SECRET_5",  "LLM_SECRET_6"]
_TOOL_KEYS = ["TOOL_SECRET_1", "TOOL_SECRET_2", "TOOL_SECRET_3",
              "TOOL_SECRET_4", "TOOL_SECRET_5", "TOOL_SECRET_6"]

_ALL_KEYS     = _LLM_KEYS + _TOOL_KEYS
_LLM_KEY_SET  = set(_LLM_KEYS)
_TOOL_KEY_SET = set(_TOOL_KEYS)

# Minimum secret value length for response scrubbing.
# Short values risk corrupting ordinary words (e.g. "pass" -> "password").
_MASK_MIN_LEN = 12


# ── module-level helpers ───────────────────────────────────────────────────────

def _pw_field(key: str, label: str) -> Any:
    """Password-masked UserValves field. Description shows the correct token."""
    token = f"${{{{{{{key}}}}}}}"
    return Field(
        default="",
        description=f"{label} | Token: {token}",
        json_schema_extra={"input": {"type": "password"}},
    )


def _vault_from_obj(obj: Any) -> Dict[str, str]:
    """
    Extract non-empty, non-whitespace secret values from a UserValves object
    or a plain dict.

    Compatible with:
      - Pydantic v2 objects (model_dump)
      - Pydantic v1 objects (dict)
      - Plain dicts
      - OW-UI 0.8.5 and 0.8.6+ return types

    Whitespace-only values are treated as unset.
    """
    if obj is None:
        return {}

    # Normalise to a plain dict regardless of Pydantic version or raw dict
    if hasattr(obj, "model_dump"):
        data = obj.model_dump()
    elif hasattr(obj, "dict"):
        data = obj.dict()
    elif isinstance(obj, dict):
        data = obj
    else:
        data = {}

    result: Dict[str, str] = {}
    for k in _ALL_KEYS:
        val = str(data.get(k, "") or "").strip()
        if val:
            result[k] = val
    return result


def _interpolate_body(
    body: Dict[str, Any],
    vault: Dict[str, str],
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Resolve LLM_SECRET_* tokens throughout the entire request body in one pass.

    - LLM_SECRET_* tokens are resolved everywhere (messages, metadata, etc.).
    - TOOL_SECRET_* tokens are always left verbatim -- never resolved.
    - Unknown tokens are left verbatim.

    Returns:
        (updated_body, list_of_missing_llm_key_names)
        A key is "missing" if its token appeared in the body but had no value
        in the vault. Tool keys are never reported as missing.
    """
    missing_llm: List[str] = []

    def replacer(m: re.Match) -> str:
        key = m.group(1)
        if key in _LLM_KEY_SET:
            if vault.get(key):
                return vault[key]
            missing_llm.append(key)
        # TOOL keys and unknown keys: always leave verbatim
        return m.group(0)

    try:
        body = json.loads(_TOKEN_RE.sub(replacer, json.dumps(body)))
    except (json.JSONDecodeError, ValueError):
        pass

    return body, missing_llm


def _scrub_body(body: Dict[str, Any], scrub_vault: Dict[str, str]) -> Dict[str, Any]:
    """
    Replace raw secret values with token placeholders throughout the body.
    Only applies to values >= _MASK_MIN_LEN to avoid corrupting ordinary words.

    Used in outlet to scrub secret values from model responses and chat history,
    preventing raw secrets from appearing in the OW-UI chat UI (e.g. tool call
    argument blocks).

    Applies to both LLM_SECRET_* and TOOL_SECRET_* values.
    """
    if not scrub_vault:
        return body
    try:
        raw = json.dumps(body)
        for key, value in scrub_vault.items():
            if value and len(value) >= _MASK_MIN_LEN:
                token = f"${{{{{{{key}}}}}}}"
                raw = raw.replace(value, token)
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return body


# ══════════════════════════════════════════════════════════════════════════════
# TOOL
# ══════════════════════════════════════════════════════════════════════════════

class Tools:
    """
    Secret Vault — per-user password-masked secret store.

    Two secret types:
      👁️  LLM_SECRET_*  : resolved in chat messages; the LLM sees the value.
      🔒  TOOL_SECRET_* : never resolved in chat; Python Tool code reads via
                          use_tool_secret().

    Users set secrets via: wrench icon 🔧 in chat → Secret Vault → person icon 👤
    """

    class UserValves(BaseModel):
        # ── LLM-visible secrets ───────────────────────────────────────────────
        LLM_SECRET_1: str = _pw_field("LLM_SECRET_1", "👁️ LLM-visible #1")
        LLM_SECRET_2: str = _pw_field("LLM_SECRET_2", "👁️ LLM-visible #2")
        LLM_SECRET_3: str = _pw_field("LLM_SECRET_3", "👁️ LLM-visible #3")
        LLM_SECRET_4: str = _pw_field("LLM_SECRET_4", "👁️ LLM-visible #4")
        LLM_SECRET_5: str = _pw_field("LLM_SECRET_5", "👁️ LLM-visible #5")
        LLM_SECRET_6: str = _pw_field("LLM_SECRET_6", "👁️ LLM-visible #6")

        # ── Tool-only secrets (Python Tool code access only) ──────────────────
        TOOL_SECRET_1: str = _pw_field("TOOL_SECRET_1", "🔒 Tool-only #1")
        TOOL_SECRET_2: str = _pw_field("TOOL_SECRET_2", "🔒 Tool-only #2")
        TOOL_SECRET_3: str = _pw_field("TOOL_SECRET_3", "🔒 Tool-only #3")
        TOOL_SECRET_4: str = _pw_field("TOOL_SECRET_4", "🔒 Tool-only #4")
        TOOL_SECRET_5: str = _pw_field("TOOL_SECRET_5", "🔒 Tool-only #5")
        TOOL_SECRET_6: str = _pw_field("TOOL_SECRET_6", "🔒 Tool-only #6")

    def __init__(self):
        self.user_valves: Optional[Tools.UserValves] = None

    async def vault_list(self) -> str:
        """List all configured secret key names (values are never shown)."""
        vault = _vault_from_obj(self.user_valves) if self.user_valves else {}
        if not vault:
            return (
                "Your vault is empty.\n"
                "Set secrets via wrench icon 🔧 → Secret Vault → person icon 👤."
            )
        llm_keys  = sorted(k for k in vault if k in _LLM_KEY_SET)
        tool_keys = sorted(k for k in vault if k in _TOOL_KEY_SET)
        lines: List[str] = [f"Vault has {len(vault)} secret(s):"]
        for heading, keys in [("👁️ LLM-visible", llm_keys),
                               ("🔒 Tool-only",   tool_keys)]:
            if keys:
                lines.append(heading + ":")
                lines += [f"  * `${{{{{{{k}}}}}}}`" for k in keys]
        return "\n".join(lines)

    async def vault_check(self, key: str) -> str:
        """
        Confirm whether a specific key is set. Value is never shown.
        :param key: Key name, e.g. LLM_SECRET_1 or TOOL_SECRET_1
        """
        vault = _vault_from_obj(self.user_valves) if self.user_valves else {}
        if key in vault:
            kind  = "🔒 Tool-only" if key in _TOOL_KEY_SET else "👁️ LLM-visible"
            token = f"${{{{{{{key}}}}}}}"
            return f"{kind} '{key}' is set. Token: `{token}`"
        available = ", ".join(sorted(vault)) if vault else "(none set)"
        return f"'{key}' is not set. Available keys: {available}"

    async def use_tool_secret(self, key_name: str) -> str:
        """
        Access a TOOL_SECRET_* value directly from Tool UserValves.
        Returns a confirmation only -- the value itself never reaches the LLM.
        :param key_name: One of TOOL_SECRET_1 through TOOL_SECRET_6.
        """
        if not self.user_valves:
            return "Error: Valves not initialised."
        if key_name not in _TOOL_KEY_SET:
            return (
                f"'{key_name}' is not a tool secret. "
                f"Valid names: {', '.join(_TOOL_KEYS)}"
            )
        if getattr(self.user_valves, key_name, ""):
            return f"Tool secret '{key_name}' retrieved successfully."
        return (
            f"'{key_name}' is not set. "
            f"Configure it via wrench icon 🔧 → Secret Vault → person icon 👤."
        )


# ══════════════════════════════════════════════════════════════════════════════
# FILTER
# ══════════════════════════════════════════════════════════════════════════════

class Filter:
    """
    Secret Vault interpolation filter.

    inlet():
      1. Fetches the requesting user's vault fresh from the OW-UI DB.
      2. Optionally resolves tokens in the admin model system prompt (opt-in).
      3. Resolves LLM_SECRET_* tokens throughout the request body.
         TOOL_SECRET_* tokens are never touched.

    outlet():
      Scrubs ALL secret values (both LLM and Tool) from the model's response
      and chat history using the vault cached by inlet, preventing raw secret
      values from appearing in the OW-UI chat UI (e.g. tool call argument
      blocks). No extra DB call.
    """

    class Valves(BaseModel):
        TOOL_ID: str = Field(
            default="",
            description=(
                "ID of the Secret Vault Tool install. "
                "Find it in the URL when editing the tool: "
                "/workspace/tools/edit/<TOOL_ID>"
            ),
        )
        OWUI_BASE_URL: str = Field(
            default="http://localhost:3000",
            description=(
                "Base URL of your Open WebUI instance (no trailing slash). "
                "Only needed if Strategy 1 (internal DB) fails."
            ),
        )
        OWUI_API_KEY: str = Field(
            default="",
            description=(
                "API key for HTTP fallback (Settings → Account → API Keys). "
                "Not required when internal DB access works."
            ),
            json_schema_extra={"input": {"type": "password"}},
        )
        enabled: bool = Field(
            default=True,
            description="Master enable/disable for the entire filter.",
        )
        warn_on_missing: bool = Field(
            default=True,
            description=(
                "Add a system-prompt warning when an LLM token can't be resolved "
                "(helps catch typos in token names)."
            ),
        )
        resolve_admin_system_prompt: bool = Field(
            default=False,
            description=(
                "Resolve ${{{LLM_SECRET_*}}} tokens in the admin model system prompt "
                "(Admin → Models → System Prompt). "
                "⚠️ OFF by default. When enabled, users control LLM_SECRET_* values "
                "which are injected verbatim into the system prompt -- a potential "
                "prompt-injection risk. Only enable if you trust all users."
            ),
        )
        debug_logging: bool = Field(
            default=False,
            description="Print [SECRET_VAULT] debug lines to Docker/server logs.",
        )

    def __init__(self):
        self.valves = Filter.Valves()
        # Request-scoped cache: inlet populates it, outlet pops it.
        # Never persisted across requests -- secret updates take effect immediately.
        self._request_cache: Dict[str, Dict[str, str]] = {}

    # ── internal helpers ───────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if getattr(self.valves, "debug_logging", False):
            print(f"[SECRET_VAULT] {msg}")

    def _fetch_user_vault(self, user_id: str) -> Dict[str, str]:
        """
        Fetch the requesting user's vault fresh on every call.

        Strategy 1 (preferred): OW-UI internal DB import.
          No network, no API key, correct per-user data.
          Compatible with OW-UI 0.8.5+ including Pydantic v2 return types.

        Strategy 2 (fallback): loopback HTTP call.
          Only useful for single-user installs where OWUI_API_KEY belongs
          to the same user making the request.
        """
        tool_id = getattr(self.valves, "TOOL_ID", "").strip()
        if not tool_id:
            self._log("TOOL_ID not configured -- cannot fetch vault")
            return {}

        # Strategy 1: direct DB access via OW-UI internal Python API
        try:
            from open_webui.models.tools import Tools as OWUITools  # type: ignore
            if OWUITools.get_tool_by_id(tool_id) is None:
                self._log(f"Tool not found: {tool_id!r}")
                return {}
            raw = OWUITools.get_user_valves_by_id_and_user_id(tool_id, user_id)
            if raw is None:
                self._log(f"No valves for user {user_id}")
                return {}
            # _vault_from_obj handles Pydantic v1, v2, and plain dicts
            vault = _vault_from_obj(raw)
            self._log(f"Strategy 1 OK: {len(vault)} key(s) for user {user_id}")
            return vault
        except ImportError:
            self._log("Strategy 1: open_webui not importable, trying HTTP")
        except Exception as exc:
            self._log(f"Strategy 1 failed: {exc}")

        # Strategy 2: loopback HTTP
        base    = getattr(self.valves, "OWUI_BASE_URL", "http://localhost:3000").rstrip("/")
        api_key = getattr(self.valves, "OWUI_API_KEY", "").strip()
        if not api_key:
            self._log("Strategy 2: OWUI_API_KEY not set, giving up")
            return {}
        url = f"{base}/api/v1/tools/{tool_id}/valves/user"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                vault = _vault_from_obj(json.loads(resp.read().decode()))
                self._log(f"Strategy 2 OK: {len(vault)} key(s)")
                return vault
        except urllib.error.HTTPError as exc:
            self._log(f"Strategy 2 HTTP {exc.code}: {exc.reason}")
        except Exception as exc:
            self._log(f"Strategy 2 failed: {exc}")
        return {}

    def _fetch_model_system_prompt(self, model_id: str) -> str:
        """
        Fetch the admin-configured system prompt for a model via OW-UI internal DB.
        Returns empty string if not found or on any error.
        """
        if not model_id:
            return ""
        try:
            from open_webui.models.models import Models as OWUIModels  # type: ignore
            model = OWUIModels.get_model_by_id(model_id)
            if model is None:
                return ""
            params = getattr(model, "params", None)
            if params is None:
                return ""
            if isinstance(params, dict):
                return params.get("system", "") or ""
            return getattr(params, "system", "") or ""
        except Exception as exc:
            self._log(f"_fetch_model_system_prompt failed: {exc}")
            return ""

    # ── filter pipeline ────────────────────────────────────────────────────────

    async def inlet(
        self,
        body: Dict[str, Any],
        __user__: Optional[Dict] = None,
        __event_emitter__: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:

        if not getattr(self.valves, "enabled", True):
            return body

        user_id = (__user__ or {}).get("id", "")
        if not user_id:
            return body

        model_id = body.get("model", "")
        vault    = self._fetch_user_vault(user_id)

        # Stash for outlet (same request, avoids second DB call)
        self._request_cache[user_id] = vault

        # Fetch admin system prompt before vault-empty check (needed for logging)
        admin_system_raw = self._fetch_model_system_prompt(model_id)

        if not vault:
            self._log("inlet: vault empty, skipping interpolation")
            return body

        # ── Optional: resolve tokens in the admin model system prompt ─────────
        _SENTINEL = "__vault_resolved_system__"
        if (
            getattr(self.valves, "resolve_admin_system_prompt", False)
            and admin_system_raw
            and _TOKEN_RE.search(admin_system_raw)
        ):
            resolved, _ = _interpolate_body({"content": admin_system_raw}, vault)
            resolved_text = resolved.get("content", admin_system_raw)
            messages = body.setdefault("messages", [])
            already_done = any(
                m.get("role") == "system" and _SENTINEL in m.get("content", "")
                for m in messages
            )
            if not already_done:
                messages.insert(0, {"role": "system", "content": resolved_text})
                self._log(f"Injected resolved admin system prompt for model {model_id!r}")

        # ── Resolve LLM tokens throughout the request body ────────────────────
        body, missing_llm = _interpolate_body(body, vault)

        # ── Warn about unresolved LLM tokens ──────────────────────────────────
        unique_missing = sorted(set(missing_llm))
        if unique_missing and getattr(self.valves, "warn_on_missing", True):
            warning = (
                "[Secret Vault] Unresolved LLM token(s): "
                + ", ".join(unique_missing)
                + ". Set them via wrench icon 🔧 → Secret Vault → person icon 👤."
            )
            messages = body.setdefault("messages", [])
            if messages and messages[0].get("role") == "system":
                messages[0]["content"] = warning + "\n\n" + messages[0]["content"]
            else:
                messages.insert(0, {"role": "system", "content": warning})
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"Secret Vault: missing {', '.join(unique_missing)}",
                        "done": True,
                    },
                })

        self._log(
            f"inlet done: {len(vault)} vault key(s), {len(unique_missing)} missing"
        )
        return body

    async def outlet(
        self,
        body: Dict[str, Any],
        __user__: Optional[Dict] = None,
        __event_emitter__: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:
        """
        Scrub ALL secret values from the model's response and chat history.

        Both LLM_SECRET_* and TOOL_SECRET_* values are replaced with their
        token placeholders, preventing raw secrets from appearing in the OW-UI
        chat UI (e.g. inside expanded tool call argument blocks).

        Uses the vault cached by inlet -- no extra DB call.
        Pops the cache entry to prevent unbounded memory growth.
        """
        user_id = (__user__ or {}).get("id", "")
        vault = self._request_cache.pop(user_id, {})
        if not vault:
            return body
        return _scrub_body(body, vault)


# ══════════════════════════════════════════════════════════════════════════════
# Self-test   python secret_vault.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import asyncio, time

    print("=== Secret Vault v6.2.0 self-test ===\n")
    checks: List[Tuple[str, bool]] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        checks.append((name, cond))
        if cond:
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}" + (f"\n      {detail}" if detail else ""))

    # ── 1. Token format ──────────────────────────────────────────────────────
    _k = "LLM_SECRET_1"
    _tok = "$" + "{{{" + _k + "}}}"
    check("token format", _tok == "${{{LLM_SECRET_1}}}", repr(_tok))

    # ── 2. _vault_from_obj: whitespace strip ─────────────────────────────────
    raw_obj = {
        "LLM_SECRET_1": "   ",
        "LLM_SECRET_2": "real-value",
        "TOOL_SECRET_1": "  \t  ",
        "TOOL_SECRET_2": "tool-val",
    }
    v = _vault_from_obj(raw_obj)
    check("vault: whitespace-only excluded",  "LLM_SECRET_1" not in v and "TOOL_SECRET_1" not in v)
    check("vault: real LLM value kept",       v.get("LLM_SECRET_2") == "real-value")
    check("vault: real TOOL value kept",      v.get("TOOL_SECRET_2") == "tool-val")

    # ── 3. _vault_from_obj: Pydantic v2 model_dump ───────────────────────────
    class FakePydanticV2:
        def model_dump(self):
            return {"LLM_SECRET_1": "from-v2", "TOOL_SECRET_1": "tool-v2"}
    v2 = _vault_from_obj(FakePydanticV2())
    check("vault: pydantic v2 model_dump",    v2.get("LLM_SECRET_1") == "from-v2")
    check("vault: pydantic v2 tool key",      v2.get("TOOL_SECRET_1") == "tool-v2")

    # ── 4. _vault_from_obj: Pydantic v1 dict ─────────────────────────────────
    class FakePydanticV1:
        def dict(self):
            return {"LLM_SECRET_2": "from-v1"}
    v1 = _vault_from_obj(FakePydanticV1())
    check("vault: pydantic v1 dict",          v1.get("LLM_SECRET_2") == "from-v1")

    # ── 5. _vault_from_obj: None safe ────────────────────────────────────────
    check("vault: None returns empty dict",   _vault_from_obj(None) == {})

    # ── 6. _interpolate_body ─────────────────────────────────────────────────
    vault = {"LLM_SECRET_1": "llm-value", "TOOL_SECRET_1": "tool-value"}
    body = {"messages": [{"role": "user",
        "content": "llm=${{{LLM_SECRET_1}}} tool=${{{TOOL_SECRET_1}}} miss=${{{LLM_SECRET_2}}}"}]}
    result, missing = _interpolate_body(body, vault)
    msg = result["messages"][0]["content"]
    check("interp: LLM resolved",          "llm-value"            in msg, msg)
    check("interp: TOOL left verbatim",    "${{{TOOL_SECRET_1}}}" in msg, msg)
    check("interp: missing LLM reported",  missing == ["LLM_SECRET_2"], str(missing))
    check("interp: TOOL not in missing",   "TOOL_SECRET_1" not in missing)
    check("interp: no double-count",       missing.count("LLM_SECRET_2") == 1)

    result2, missing2 = _interpolate_body(
        {"messages": [{"role": "user", "content": "${{{LLM_SECRET_1}}}"}]}, {}
    )
    check("interp: missing token stays verbatim",
          result2["messages"][0]["content"] == "${{{LLM_SECRET_1}}}")

    # ── 7. _scrub_body: scrubs both LLM and TOOL secrets ─────────────────────
    long_tool = "sk-abc123def456ghi789xyz"   # 23 chars
    long_llm  = "llm-visible-value-1234567"  # 24 chars
    short_val = "pass"                        # 4 chars -- must NOT be masked
    scrub_v = {
        "LLM_SECRET_1":  long_llm,
        "TOOL_SECRET_1": long_tool,
        "TOOL_SECRET_2": short_val,
    }
    body3 = {"messages": [{"role": "assistant",
        "content": f"tool={long_tool} llm={long_llm} short={short_val}"}]}
    out3 = _scrub_body(body3, scrub_v)["messages"][0]["content"]
    check("scrub: long TOOL replaced",     "${{{TOOL_SECRET_1}}}" in out3, out3)
    check("scrub: long LLM replaced",      "${{{LLM_SECRET_1}}}"  in out3, out3)
    check("scrub: short NOT replaced",     short_val in out3, out3)

    # ── 8. No ReDoS ──────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    _TOKEN_RE.search("${{{" + "A" * 10000 + "}}}")
    check("no ReDoS on 10k input", time.perf_counter() - t0 < 0.1)

    # ── 9. Tool.use_tool_secret ───────────────────────────────────────────────
    async def run_tool_tests():
        t = Tools()
        uv = Tools.UserValves()
        uv.TOOL_SECRET_1 = "some-secret-value"
        t.user_valves = uv
        r1 = await t.use_tool_secret("TOOL_SECRET_1")
        check("use_tool_secret: success",          "successfully" in r1.lower(), r1)
        check("use_tool_secret: value not in msg", "some-secret" not in r1, r1)
        r2 = await t.use_tool_secret("TOOL_SECRET_2")
        check("use_tool_secret: unset msg",        "not set" in r2.lower(), r2)
        r3 = await t.use_tool_secret("LLM_SECRET_1")
        check("use_tool_secret: rejects LLM",      "not a tool secret" in r3.lower(), r3)
    asyncio.run(run_tool_tests())

    # ── 10. Filter.inlet end-to-end ──────────────────────────────────────────
    async def run_inlet_tests():
        f = Filter()
        f.valves.enabled = True
        f.valves.warn_on_missing = True
        f.valves.resolve_admin_system_prompt = False
        f._fetch_user_vault          = lambda uid: {
            "LLM_SECRET_1": "my-llm-key",
            "TOOL_SECRET_1": "my-tool-secret-abc",
        }
        f._fetch_model_system_prompt = lambda mid: ""
        body_in = {
            "model": "test-model",
            "messages": [{"role": "user", "content":
                "llm=${{{LLM_SECRET_1}}} tool=${{{TOOL_SECRET_1}}} miss=${{{LLM_SECRET_2}}}"}],
        }
        result = await f.inlet(body_in, __user__={"id": "u1"})
        msgs     = result["messages"]
        user_msg = next(m for m in msgs if m["role"] == "user")["content"]
        sys_msg  = next((m for m in msgs if m["role"] == "system"), None)
        check("inlet: LLM resolved",          "my-llm-key"          in user_msg, user_msg)
        check("inlet: TOOL verbatim",         "${{{TOOL_SECRET_1}}}" in user_msg, user_msg)
        check("inlet: warn for missing",      sys_msg is not None)
        check("inlet: warn names missing key",
              sys_msg and "LLM_SECRET_2" in sys_msg["content"], str(sys_msg))
        check("inlet: warn omits TOOL key",
              sys_msg and "TOOL_SECRET_1" not in sys_msg["content"], str(sys_msg))
        check("inlet: cache populated",       "u1" in f._request_cache)
        # Confirm resolved value is NOT re-masked by inlet (the 6.1.0 bug)
        check("inlet: resolved value not re-masked",
              "${{{LLM_SECRET_1}}}" not in user_msg, user_msg)
    asyncio.run(run_inlet_tests())

    # ── 11. Filter.outlet scrubs both LLM and TOOL secrets ───────────────────
    async def run_outlet_tests():
        f = Filter()
        f._request_cache["u2"] = {
            "LLM_SECRET_1":  "my-llm-key-abcdef1234",
            "TOOL_SECRET_1": "my-tool-secret-abc123",
        }
        body_out = {"messages": [{"role": "assistant",
            "content": "tool=my-tool-secret-abc123 llm=my-llm-key-abcdef1234"}]}
        result = await f.outlet(body_out, __user__={"id": "u2"})
        out = result["messages"][0]["content"]
        check("outlet: TOOL value scrubbed",    "${{{TOOL_SECRET_1}}}" in out, out)
        check("outlet: LLM value scrubbed",     "${{{LLM_SECRET_1}}}"  in out, out)
        check("outlet: cache popped",           "u2" not in f._request_cache)
        body_pass = {"messages": [{"role": "assistant", "content": "hello"}]}
        result_pass = await f.outlet(body_pass, __user__={"id": "unknown"})
        check("outlet: no cache -> passthrough", result_pass == body_pass)
    asyncio.run(run_outlet_tests())

    # ── 12. Fresh fetch every request ────────────────────────────────────────
    async def run_freshness_test():
        f = Filter()
        f.valves.warn_on_missing = False
        f.valves.resolve_admin_system_prompt = False
        count = [0]
        def mock_fetch(uid):
            count[0] += 1
            return {"LLM_SECRET_1": "value-" + str(count[0])}
        f._fetch_user_vault          = mock_fetch
        f._fetch_model_system_prompt = lambda mid: ""
        for _ in range(3):
            await f.inlet({"model": "m", "messages": [{"role": "user", "content": "hi"}]},
                          __user__={"id": "u3"})
            f._request_cache.pop("u3", None)
        check("fresh DB fetch every request", count[0] == 3)
    asyncio.run(run_freshness_test())

    # ── 13. resolve_admin_system_prompt valve ─────────────────────────────────
    async def run_admin_tests():
        def make_filter(vault, prompt, valve):
            f = Filter()
            f.valves.warn_on_missing = False
            f.valves.resolve_admin_system_prompt = valve
            f._fetch_user_vault          = lambda uid: vault
            f._fetch_model_system_prompt = lambda mid: prompt
            return f

        f_off = make_filter({"LLM_SECRET_1": "s"}, "p=${{{LLM_SECRET_1}}}", False)
        r_off = await f_off.inlet(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            __user__={"id": "u4"})
        sys_off = [m for m in r_off["messages"] if m["role"] == "system"]
        check("admin prompt: NOT injected when valve=False", len(sys_off) == 0)

        f_on = make_filter({"LLM_SECRET_1": "secret-val"}, "p=${{{LLM_SECRET_1}}}", True)
        r_on = await f_on.inlet(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            __user__={"id": "u5"})
        sys_on = [m for m in r_on["messages"] if m["role"] == "system"]
        check("admin prompt: injected when valve=True",    len(sys_on) == 1)
        check("admin prompt: token resolved",
              sys_on and "secret-val" in sys_on[0]["content"], str(sys_on))
        check("admin prompt: raw token absent",
              sys_on and "${{{LLM_SECRET_1}}}" not in sys_on[0]["content"], str(sys_on))
    asyncio.run(run_admin_tests())

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    failed = [name for name, ok in checks if not ok]
    if failed:
        print(f"FAILED {len(failed)}/{len(checks)}:")
        for name in failed:
            print(f"  ✗ {name}")
    else:
        print(f"All {len(checks)} checks passed ✓")
