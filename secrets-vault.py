"""
title: Secret Vault
author: open-webui-plugin
version: 5.3.0
description: >
  Per-user secret key/value store with password-masked UI.

  KEY TYPES:
    - LLM Secrets (LLM_SECRET_1 through LLM_SECRET_6):
      Interpolated in chat prompts. The LLM sees the actual value.
    - Tool Secrets (TOOL_SECRET_1 through TOOL_SECRET_6):
      NEVER interpolated in chat. Only Tool code accesses the real value.

  SETUP:
    1. Install as TOOL   (Workspace -> Tools -> Add Tool)
    2. Install as FILTER (Admin -> Functions -> Add Function, enable, Global)
    3. Configure Filter Valves (gear icon on the Function):
         TOOL_ID       : from URL when editing tool: /workspace/tools/edit/<ID>
         OWUI_BASE_URL : e.g. http://localhost:3000
         OWUI_API_KEY  : only needed if internal DB access fails (rare)
    4. Each user sets secrets via wrench icon -> Secret Vault -> person icon

  USAGE:
    ${{{LLM_SECRET_1}}}  -> resolved before the LLM sees the message
    ${{{TOOL_SECRET_1}}} -> left as-is in chat; Tool code reads raw value

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
        return None


# ── token pattern ─────────────────────────────────────────────────────────────
_TOKEN_RE = re.compile(r"\$\{\{\{([A-Za-z0-9_]+)\}\}\}")

# ── key groups ────────────────────────────────────────────────────────────────
_LLM_KEYS = [
    "LLM_SECRET_1",
    "LLM_SECRET_2",
    "LLM_SECRET_3",
    "LLM_SECRET_4",
    "LLM_SECRET_5",
    "LLM_SECRET_6",
]
_TOOL_KEYS = [
    "TOOL_SECRET_1",
    "TOOL_SECRET_2",
    "TOOL_SECRET_3",
    "TOOL_SECRET_4",
    "TOOL_SECRET_5",
    "TOOL_SECRET_6",
]
_ALL_KEYS = _LLM_KEYS + _TOOL_KEYS
_TOOL_KEY_SET = set(_TOOL_KEYS)
_LLM_KEY_SET = set(_LLM_KEYS)

# Minimum secret length for outlet masking.
# Short values risk corrupting ordinary text via partial str.replace matches
# (e.g. secret="pass" would mangle the word "password").
# Real secrets (API keys, tokens, passwords) are virtually always >= 12 chars.
_MASK_MIN_LEN = 12


# ── helpers ───────────────────────────────────────────────────────────────────


def _pw_field(key: str, label: str) -> Any:
    """Password-masked UserValves field with correct triple-brace token hint."""
    # Seven braces needed: ${ + {{ + key + }} + } = ${{{KEY}}}
    token = f"${{{{{{{key}}}}}}}"
    return Field(
        default="",
        description=f"{label} | Token: {token}",
        json_schema_extra={"input": {"type": "password"}},
    )


def _interpolate_body(
    body: Dict[str, Any], vault: Dict[str, str]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Interpolate LLM tokens throughout the entire request body in one pass.

    - Resolves ${{{KEY}}} only for keys in _LLM_KEYS.
    - Tool-key tokens are left verbatim (not treated as missing).
    - Returns (updated_body, list_of_genuinely_missing_llm_keys).
    """
    missing_llm: List[str] = []

    def replacer(m: re.Match) -> str:
        key = m.group(1)
        if key in _LLM_KEY_SET:
            if key in vault and vault[key]:
                return vault[key]
            missing_llm.append(key)
        # Tool keys and unknown keys: leave verbatim, never mark as missing
        return m.group(0)

    try:
        raw = json.dumps(body)
        interpolated = _TOKEN_RE.sub(replacer, raw)
        body = json.loads(interpolated)
    except (json.JSONDecodeError, ValueError):
        pass

    return body, missing_llm


def _mask_tool_secrets(text: str, tool_vault: Dict[str, str]) -> str:
    """
    Replace raw tool-secret values with their token placeholders in a string.

    Only masks values >= _MASK_MIN_LEN characters to prevent partial-match
    corruption of ordinary words (e.g. a 4-char secret "pass" would mangle
    "password" -> "${{{TOOL_SECRET_1}}}word").
    """
    for key, value in tool_vault.items():
        if value and len(value) >= _MASK_MIN_LEN:
            text = text.replace(value, f"${{{{{{{key}}}}}}}")
    return text


def _mask_body_tool_secrets(
    body: Dict[str, Any], tool_vault: Dict[str, str]
) -> Dict[str, Any]:
    """Apply _mask_tool_secrets across the entire serialised body."""
    if not tool_vault:
        return body
    try:
        raw = json.dumps(body)
        for key, value in tool_vault.items():
            if value and len(value) >= _MASK_MIN_LEN:
                raw = raw.replace(value, f"${{{{{{{key}}}}}}}")
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return body


def _vault_from_obj(obj: Any) -> Dict[str, str]:
    """Extract non-empty vault fields from a UserValves object or plain dict."""
    result: Dict[str, str] = {}
    for k in _ALL_KEYS:
        v = obj.get(k, "") if isinstance(obj, dict) else getattr(obj, k, "")
        if isinstance(v, str):
            v = v.strip()  # treat whitespace-only values as unset
        if v:
            result[k] = v
    return result


# ================================================================================
# TOOL
# ================================================================================


class Tools:
    """
    Secret Vault -- per-user password-masked secret store.

    LLM Secrets  (LLM_SECRET_*)  : resolved in chat before the model sees them.
    Tool Secrets (TOOL_SECRET_*)  : never sent to the model; Tool code reads them.

    Set secrets via: wrench icon in chat -> Secret Vault -> person icon.
    """

    class UserValves(BaseModel):
        # -- LLM-visible secrets ----------------------------------------------
        LLM_SECRET_1: str = _pw_field("LLM_SECRET_1", "👁️ LLM-visible #1")
        LLM_SECRET_2: str = _pw_field("LLM_SECRET_2", "👁️ LLM-visible #2")
        LLM_SECRET_3: str = _pw_field("LLM_SECRET_3", "👁️ LLM-visible #3")
        LLM_SECRET_4: str = _pw_field("LLM_SECRET_4", "👁️ LLM-visible #4")
        LLM_SECRET_5: str = _pw_field("LLM_SECRET_5", "👁️ LLM-visible #5")
        LLM_SECRET_6: str = _pw_field("LLM_SECRET_6", "👁️ LLM-visible #6")

        # -- Tool-only secrets ------------------------------------------------
        TOOL_SECRET_1: str = _pw_field("TOOL_SECRET_1", "🔒 Tool-only #1")
        TOOL_SECRET_2: str = _pw_field("TOOL_SECRET_2", "🔒 Tool-only #2")
        TOOL_SECRET_3: str = _pw_field("TOOL_SECRET_3", "🔒 Tool-only #3")
        TOOL_SECRET_4: str = _pw_field("TOOL_SECRET_4", "🔒 Tool-only #4")
        TOOL_SECRET_5: str = _pw_field("TOOL_SECRET_5", "🔒 Tool-only #5")
        TOOL_SECRET_6: str = _pw_field("TOOL_SECRET_6", "🔒 Tool-only #6")

    def __init__(self):
        self.user_valves: Optional[Tools.UserValves] = None

    async def vault_list(self) -> str:
        """List all configured secret key names. Values are never shown."""
        vault = _vault_from_obj(self.user_valves) if self.user_valves else {}
        if not vault:
            return (
                "Your vault is empty.\n"
                "Set secrets via wrench icon -> Secret Vault -> person icon."
            )
        llm_keys = sorted(k for k in vault if k in _LLM_KEY_SET)
        tool_keys = sorted(k for k in vault if k in _TOOL_KEY_SET)
        lines: List[str] = []
        if llm_keys:
            lines.append("👁️ LLM-visible:")
            lines += [f"  * ${{{{{{{k}}}}}}}" for k in llm_keys]
        if tool_keys:
            lines.append("🔒 Tool-only:")
            lines += [f"  * ${{{{{{{k}}}}}}}" for k in tool_keys]
        return f"Vault has {len(vault)} secret(s):\n" + "\n".join(lines)

    async def vault_check(self, key: str) -> str:
        """
        Check whether a specific key is set. Value is never shown.
        :param key: Key name to check, e.g. LLM_SECRET_1
        """
        vault = _vault_from_obj(self.user_valves) if self.user_valves else {}
        if key in vault:
            kind = "🔒 Tool-only" if key in _TOOL_KEY_SET else "👁️ LLM-visible"
            return f"{kind} '{key}' is set. Token: ${{{{{{{key}}}}}}}"
        available = ", ".join(sorted(vault)) if vault else "(none set)"
        return f"'{key}' is not set. Available: {available}"

    async def use_tool_secret(self, key_name: str) -> str:
        """
        Access a tool-only secret value directly from Tool valves.
        The value is returned to the Tool caller and never reaches the LLM.
        :param key_name: One of TOOL_SECRET_1 through TOOL_SECRET_6.
        """
        if not self.user_valves:
            return "Error: Valves not initialised."
        if key_name not in _TOOL_KEY_SET:
            return (
                f"'{key_name}' is not a tool secret. "
                f"Valid names: {', '.join(_TOOL_KEYS)}"
            )
        secret = getattr(self.user_valves, key_name, "")
        if secret:
            # Return only confirmation -- never the value or its length
            return f"Tool secret '{key_name}' retrieved successfully."
        return (
            f"'{key_name}' is not set. "
            f"Configure it via wrench icon -> Secret Vault -> person icon."
        )


# ================================================================================
# FILTER
# ================================================================================


class Filter:
    """
    Secret Vault interpolation filter.

    Resolves LLM tokens and masks tool secrets in one efficient body-level pass.
    Fetches per-user secrets via OW-UI internal DB (Strategy 1) with HTTP
    fallback (Strategy 2).
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
            description="Base URL of your Open WebUI instance (no trailing slash).",
        )
        OWUI_API_KEY: str = Field(
            default="",
            description=(
                "API key for HTTP fallback only (Settings -> Account -> API Keys). "
                "Not required when internal DB access works (Strategy 1)."
            ),
            json_schema_extra={"input": {"type": "password"}},
        )
        enabled: bool = Field(default=True, description="Master enable/disable.")
        warn_on_missing: bool = Field(
            default=True,
            description="Inject a system-prompt warning for unresolved LLM tokens.",
        )
        resolve_admin_system_prompt: bool = Field(
            default=False,
            description=(
                "Fetch and resolve tokens in the admin-configured model system prompt. "
                "⚠️ Security note: LLM secrets are injected verbatim into the system prompt, "
                "so a user controlling LLM_SECRET_* values could craft adversarial instructions. "
                "Only enable this if you trust all users who can set LLM secrets."
            ),
        )
        debug_logging: bool = Field(
            default=False,
            description="Print debug info to Docker/server logs.",
        )

    def __init__(self):
        self.valves = Filter.Valves()
        # Request-scoped vault cache: populated by inlet, consumed by outlet.
        # Keyed by user_id. Lives only for the duration of one request
        # (inlet sets it, outlet reads it, then it is cleared).
        # This avoids stale secrets if the user updates their vault between requests,
        # while still sparing outlet the cost of a second DB fetch.
        self._request_cache: Dict[str, Dict[str, str]] = {}

    def _log(self, msg: str) -> None:
        if getattr(self.valves, "debug_logging", False):
            print(f"[SECRET_VAULT] {msg}")

    def _fetch_user_vault(self, user_id: str) -> Dict[str, str]:
        """
        Fetch this user's Tool UserValves fresh on every request (Strategy 1),
        falling back to HTTP (Strategy 2) if internal DB import fails.

        We deliberately do NOT cache permanently across requests -- if a user
        updates their secrets the change takes effect immediately on the next
        message, with no server restart required.

        outlet() reads from self._request_cache which is populated by inlet()
        for the same request, avoiding a second DB fetch per response.
        """

        tool_id = getattr(self.valves, "TOOL_ID", "").strip()
        if not tool_id:
            self._log("TOOL_ID not configured in Filter Valves")
            return {}

        # ── Strategy 1: internal DB ───────────────────────────────────────
        try:
            from open_webui.models.tools import Tools as OWUITools  # type: ignore

            tool = OWUITools.get_tool_by_id(tool_id)
            if tool is None:
                self._log(f"Tool not found: {tool_id}")
                return {}

            user_valves = OWUITools.get_user_valves_by_id_and_user_id(tool_id, user_id)
            if user_valves is None:
                self._log(f"No valves set for user {user_id}")
                return {}

            vault = _vault_from_obj(
                user_valves
                if isinstance(user_valves, dict)
                else user_valves.model_dump()
            )
            self._log(f"Strategy 1 OK: {len(vault)} keys for user {user_id}")
            return vault

        except ImportError:
            self._log("Strategy 1: open_webui not importable, trying HTTP")
        except Exception as e:
            self._log(f"Strategy 1 failed: {e}")

        # ── Strategy 2: HTTP loopback ─────────────────────────────────────
        base = getattr(self.valves, "OWUI_BASE_URL", "http://localhost:3000").rstrip(
            "/"
        )
        api_key = getattr(self.valves, "OWUI_API_KEY", "").strip()

        if not api_key:
            self._log("Strategy 2: OWUI_API_KEY not set, giving up")
            return {}

        url = f"{base}/api/v1/tools/{tool_id}/valves/user"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                vault = _vault_from_obj(data)
                self._log(f"Strategy 2 OK: {len(vault)} keys")
                return vault
        except urllib.error.HTTPError as e:
            self._log(f"Strategy 2 HTTP {e.code}: {e.reason}")
        except Exception as e:
            self._log(f"Strategy 2 failed: {e}")

        return {}

    def _fetch_model_system_prompt(self, model_id: str) -> str:
        """
        Fetch the admin-configured system prompt for a model via internal DB.
        The system prompt lives at model.params.system (Pydantic attribute).
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
            # params is a Pydantic model with a .system attribute
            # (confirmed on OW-UI 0.8.5 via field dump)
            if isinstance(params, dict):
                return params.get("system", "") or ""
            return getattr(params, "system", "") or ""
        except Exception as e:
            self._log(f"_fetch_model_system_prompt failed: {e}")
            return ""

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
        vault = self._fetch_user_vault(user_id)

        # Stash for outlet to use without a second DB call this request
        self._request_cache[user_id] = vault

        _VAULT_SENTINEL = "__vault_resolved_system__"
        admin_system_raw = self._fetch_model_system_prompt(model_id)

        if not vault:
            return body

        # ── Resolve admin model system prompt (injected AFTER filter normally) ──
        # The admin system prompt from Admin -> Models -> System Prompt is NOT
        # present in body["messages"] when inlet runs -- OW-UI appends it later.
        # We fetch it directly, interpolate it with the user's vault, then inject
        # it as the first system message so the LLM sees the resolved version.
        # OW-UI will still append the raw admin prompt later, resulting in two
        # system messages -- we mark ours with a sentinel so we can detect this.
        if (
            getattr(self.valves, "resolve_admin_system_prompt", False)
            and admin_system_raw
            and _TOKEN_RE.search(admin_system_raw)
        ):
            resolved_system, sys_missing = _interpolate_body(
                {"content": admin_system_raw}, vault
            )
            resolved_text = resolved_system.get("content", admin_system_raw)
            messages = body.setdefault("messages", [])
            # Check if OW-UI already injected the admin system prompt (rare but possible)
            already_injected = any(
                m.get("role") == "system" and _VAULT_SENTINEL in m.get("content", "")
                for m in messages
            )
            if not already_injected:
                # Prepend resolved system prompt; OW-UI's raw copy will be a duplicate
                # but most models treat multiple system messages fine, and the resolved
                # one takes precedence as it appears first.
                messages.insert(
                    0,
                    {
                        "role": "system",
                        "content": resolved_text,
                    },
                )
                self._log(f"Injected resolved admin system prompt for model {model_id}")

        # ── Single-pass: interpolate LLM keys + mask tool secrets ─────────
        # One JSON serialise/deserialise covers all messages, metadata,
        # MCP env blocks, tool args -- everything. No double-counting.
        body, missing_llm = _interpolate_body(body, vault)

        tool_vault = {k: v for k, v in vault.items() if k in _TOOL_KEY_SET}
        body = _mask_body_tool_secrets(body, tool_vault)

        # ── Warn about genuinely unresolved LLM tokens ────────────────────
        unique_missing = sorted(set(missing_llm))
        if unique_missing and getattr(self.valves, "warn_on_missing", True):
            warning = (
                "[Secret Vault] Unresolved LLM token(s): "
                + ", ".join(unique_missing)
                + ". Set them via wrench icon -> Secret Vault -> person icon."
            )
            messages = body.setdefault("messages", [])
            if messages and messages[0].get("role") == "system":
                messages[0]["content"] = warning + "\n\n" + messages[0]["content"]
            else:
                messages.insert(0, {"role": "system", "content": warning})

            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"Secret Vault: missing: {', '.join(unique_missing)}",
                            "done": True,
                        },
                    }
                )

        self._log(f"inlet done. resolved LLM keys, {len(missing_llm)} missing")
        return body

    async def outlet(
        self,
        body: Dict[str, Any],
        __user__: Optional[Dict] = None,
        __event_emitter__: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ) -> Dict[str, Any]:
        """
        Scrub tool secret values from the model's response.

        Uses the in-memory cache populated by inlet -- no extra DB/HTTP call.
        If no tool secrets are set for this user, returns immediately.
        """
        user_id = (__user__ or {}).get("id", "")
        # Use the request-scoped cache set by inlet -- no extra DB call.
        # Pop it so memory doesn't grow unbounded on long-running servers.
        vault = self._request_cache.pop(user_id, {})
        tool_vault = {k: v for k, v in vault.items() if k in _TOOL_KEY_SET}
        if not tool_vault:
            return body
        return _mask_body_tool_secrets(body, tool_vault)


# ================================================================================
# Self-test  (python secret_vault.py)
# ================================================================================

if __name__ == "__main__":
    import asyncio

    print("=== Secret Vault v5.3 self-test ===\n")
    checks = []  # list of (name, passed)

    def check(name: str, condition: bool, detail: str = ""):
        checks.append((name, condition))
        if condition:
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}" + (f": {detail}" if detail else ""))

    # ── token display: field descriptions show correct triple-brace tokens ──
    k = "LLM_SECRET_1"
    token = f"${{{{{{{k}}}}}}}"
    check("token format", token == "${{{LLM_SECRET_1}}}", token)

    # ── _interpolate_body: LLM resolves, tool stays, no double-count ────────
    vault = {
        "LLM_SECRET_1": "llm-value",
        "TOOL_SECRET_1": "tool-value",
    }
    body = {
        "messages": [
            {
                "role": "user",
                "content": "llm=${{{LLM_SECRET_1}}} tool=${{{TOOL_SECRET_1}}} miss=${{{LLM_SECRET_2}}}",
            }
        ]
    }
    result, missing = _interpolate_body(body, vault)
    msg = result["messages"][0]["content"]
    check("LLM token resolved", "llm-value" in msg, msg)
    check("TOOL token left verbatim", "${{{TOOL_SECRET_1}}}" in msg, msg)
    check("LLM missing reported", missing == ["LLM_SECRET_2"], str(missing))
    check("TOOL not in missing", "TOOL_SECRET_1" not in missing, str(missing))
    check("no double-count", missing.count("LLM_SECRET_2") == 1, str(missing))

    # ── _mask_tool_secrets: long secret masked, short secret skipped ─────────
    long_secret = "sk-abc123def456ghi789xyz"  # 23 chars
    short_secret = "pass"  # 4 chars -- must NOT be masked
    tv = {"TOOL_SECRET_1": long_secret, "TOOL_SECRET_2": short_secret}
    body2 = {
        "messages": [
            {
                "role": "assistant",
                "content": f"token={long_secret} and my password is short_secret",
            }
        ]
    }
    result2 = _mask_body_tool_secrets(body2, tv)
    out = result2["messages"][0]["content"]
    check("long secret masked in outlet", "${{{TOOL_SECRET_1}}}" in out, out)
    check("short secret NOT masked", short_secret in out, out)
    check("'password' not corrupted", "password" in out, out)

    # ── outlet uses cache, no fetch ──────────────────────────────────────────
    async def run_outlet_test():
        filt = Filter()
        filt.valves.enabled = True
        filt._request_cache["u1"] = {"TOOL_SECRET_1": long_secret}
        # If outlet tried to fetch it would fail (no TOOL_ID set)
        body3 = {
            "messages": [{"role": "assistant", "content": f"value is {long_secret}"}]
        }
        result3 = await filt.outlet(body3, __user__={"id": "u1"})
        out3 = result3["messages"][0]["content"]
        check(
            "outlet uses request_cache not fetch", "${{{TOOL_SECRET_1}}}" in out3, out3
        )

        # user with no cache entry -> passthrough unchanged
        body4 = {"messages": [{"role": "assistant", "content": "hello"}]}
        result4 = await filt.outlet(body4, __user__={"id": "unknown-user"})
        check("outlet empty cache -> passthrough", result4 == body4)

    asyncio.run(run_outlet_test())

    # ── use_tool_secret: no length leak ─────────────────────────────────────
    async def run_tool_test():
        tools = Tools()
        uv = Tools.UserValves()
        uv.TOOL_SECRET_1 = "some-secret-value"
        tools.user_valves = uv
        resp = await tools.use_tool_secret("TOOL_SECRET_1")
        check("use_tool_secret no length leak", "length" not in resp.lower(), resp)
        check("use_tool_secret success msg", "successfully" in resp.lower(), resp)
        resp2 = await tools.use_tool_secret("TOOL_SECRET_2")
        check("use_tool_secret unset msg", "not set" in resp2.lower(), resp2)
        resp3 = await tools.use_tool_secret("LLM_SECRET_1")
        check(
            "use_tool_secret rejects non-tool key",
            "not a tool secret" in resp3.lower(),
            resp3,
        )

    asyncio.run(run_tool_test())

    # ── inlet end-to-end with mocked fetch ───────────────────────────────────
    async def run_inlet_test():
        filt = Filter()
        filt.valves.enabled = True
        filt.valves.warn_on_missing = True
        filt._fetch_user_vault = lambda uid: {
            "LLM_SECRET_1": "my-api-key",
            "TOOL_SECRET_1": "super-secret-tool-password",
        }
        body5 = {
            "messages": [
                {
                    "role": "user",
                    "content": "key=${{{LLM_SECRET_1}}} tool=${{{TOOL_SECRET_1}}} miss=${{{LLM_SECRET_2}}}",
                }
            ]
        }
        result5 = await filt.inlet(body5, __user__={"id": "u2"})
        msgs = result5["messages"]
        user_msg = next(m for m in msgs if m["role"] == "user")["content"]
        sys_msg = next((m for m in msgs if m["role"] == "system"), None)
        check("inlet: LLM resolved", "my-api-key" in user_msg, user_msg)
        check("inlet: TOOL left verbatim", "${{{TOOL_SECRET_1}}}" in user_msg, user_msg)
        check("inlet: warning for missing", sys_msg is not None)
        check(
            "inlet: warning names LLM_SECRET_2",
            sys_msg and "LLM_SECRET_2" in sys_msg["content"],
            str(sys_msg),
        )
        check(
            "inlet: warning omits TOOL key",
            sys_msg and "TOOL_SECRET_1" not in sys_msg["content"],
            str(sys_msg),
        )

    asyncio.run(run_inlet_test())

    # ── whitespace strip ─────────────────────────────────────────────────────
    ws_obj = {
        "LLM_SECRET_1": "   ",
        "LLM_SECRET_2": "real-value",
        "TOOL_SECRET_1": "  ",
    }
    ws_vault = _vault_from_obj(ws_obj)
    checks.append(
        (
            "whitespace stripped: spaces-only not stored",
            "LLM_SECRET_1" not in ws_vault and "TOOL_SECRET_1" not in ws_vault,
        )
    )
    checks.append(
        (
            "whitespace stripped: real value kept",
            ws_vault.get("LLM_SECRET_2") == "real-value",
        )
    )

    # ── resolve_admin_system_prompt valve ────────────────────────────────────
    async def run_admin_prompt_test():
        filt = Filter()
        filt.valves.enabled = True
        filt.valves.warn_on_missing = False
        filt._fetch_user_vault = lambda uid: {"LLM_SECRET_1": "resolved-value"}

        # When valve is OFF (default) -- admin system prompt NOT resolved
        filt.valves.resolve_admin_system_prompt = False
        filt._fetch_model_system_prompt = lambda mid: "system=${{{LLM_SECRET_1}}}"
        body_off = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}
        result_off = await filt.inlet(body_off, __user__={"id": "u1"})
        sys_msgs_off = [m for m in result_off["messages"] if m["role"] == "system"]
        checks.append(
            ("admin prompt NOT injected when valve=False", len(sys_msgs_off) == 0)
        )

        # When valve is ON -- admin system prompt IS resolved and injected
        filt.valves.resolve_admin_system_prompt = True
        body_on = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}
        result_on = await filt.inlet(body_on, __user__={"id": "u2"})
        sys_msgs_on = [m for m in result_on["messages"] if m["role"] == "system"]
        checks.append(("admin prompt injected when valve=True", len(sys_msgs_on) == 1))
        checks.append(
            (
                "admin prompt token resolved",
                sys_msgs_on and "resolved-value" in sys_msgs_on[0]["content"],
            )
        )
        checks.append(
            (
                "raw token not in injected msg",
                sys_msgs_on and "${{{LLM_SECRET_1}}}" not in sys_msgs_on[0]["content"],
            )
        )

    asyncio.run(run_admin_prompt_test())

    # ── request cache cleared after outlet ───────────────────────────────────
    async def run_cache_test():
        filt = Filter()
        filt.valves.enabled = True
        filt.valves.warn_on_missing = False
        filt.valves.resolve_admin_system_prompt = False
        fetch_count = [0]

        def counting_fetch(uid):
            fetch_count[0] += 1
            return {"TOOL_SECRET_1": "sk-abc123def456ghi789xyz"}

        filt._fetch_user_vault = counting_fetch
        filt._fetch_model_system_prompt = lambda mid: ""

        body_in = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        await filt.inlet(body_in, __user__={"id": "u3"})
        checks.append(("inlet fetches vault once", fetch_count[0] == 1))
        checks.append(
            ("request_cache populated after inlet", "u3" in filt._request_cache)
        )

        body_out = {"messages": [{"role": "assistant", "content": "hi back"}]}
        await filt.outlet(body_out, __user__={"id": "u3"})
        checks.append(("outlet pops cache (no second fetch)", fetch_count[0] == 1))
        checks.append(
            ("request_cache cleared after outlet", "u3" not in filt._request_cache)
        )

    asyncio.run(run_cache_test())

    # ── print results ─────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    passed = [(n, ok) for n, ok in checks if ok]
    failed = [(n, ok) for n, ok in checks if not ok]
    for name, _ in failed:
        print(f"FAIL  {name}")
    if failed:
        print(f"\nFAILED {len(failed)}/{len(checks)}")
    else:
        print(f"All {len(checks)} checks passed.")

