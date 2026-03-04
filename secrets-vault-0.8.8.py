"""
title: Secret Vault (v6.0.0 - Stealth Mode)
author: open-webui-plugin
version: 6.0.0
description: >
  Per-user secret vault with full UI masking. Replaces raw secrets with tokens 
  in tool call arguments and chat history to prevent leaks.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

try:
    from pydantic import BaseModel, Field
except ImportError:
    class BaseModel: pass
    def Field(*a, **kw): return None

# ── Shared Logic & Regex ──────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"\$\{\{\{([A-Za-z0-9_]+)\}\}\}")
_LLM_KEYS = [f"LLM_SECRET_{i}" for i in range(1, 7)]
_TOOL_KEYS = [f"TOOL_SECRET_{i}" for i in range(1, 7)]
_ALL_KEYS = _LLM_KEYS + _TOOL_KEYS
_TOOL_KEY_SET = set(_TOOL_KEYS)
_LLM_KEY_SET = set(_LLM_KEYS)
_MASK_MIN_LEN = 10  # Secrets shorter than this won't be masked to avoid false positives

def _vault_from_obj(obj: Any) -> Dict[str, str]:
    """Robust extractor for OWUI 0.8.8 Pydantic v2 schemas."""
    result = {}
    if obj is None: return result
    if hasattr(obj, "model_dump"): data = obj.model_dump()
    elif hasattr(obj, "dict"): data = obj.dict()
    elif isinstance(obj, dict): data = obj
    else: data = {}

    for k in _ALL_KEYS:
        val = data.get(k, "")
        if val is None: val = ""
        val_str = str(val).strip()
        if val_str: result[k] = val_str
    return result

def _pw_field(key: str, label: str) -> Any:
    return Field(default="", description=f"{label} | Token: ${{{{{{{key}}}}}}}", json_schema_extra={"input": {"type": "password"}})

def _mask_sensitive_data(body: Dict[str, Any], vault: Dict[str, str]) -> Dict[str, Any]:
    """Scans the entire body and replaces raw secrets with their tokens."""
    if not vault: return body
    try:
        raw_json = json.dumps(body)
        for key, value in vault.items():
            # Only mask if the value is long enough to be a unique secret
            if value and len(value) >= _MASK_MIN_LEN:
                token = f"${{{{{{{key}}}}}}}"
                raw_json = raw_json.replace(value, token)
        return json.loads(raw_json)
    except:
        return body

# ================================================================================
# TOOL
# ================================================================================

class Tools:
    class Valves(BaseModel):
        TOOL_ID: str = Field(default="", description="MANDATORY: Paste the Tool ID here from your browser URL.")

    class UserValves(BaseModel):
        LLM_SECRET_1: str = _pw_field("LLM_SECRET_1", "👁️ LLM-visible #1")
        LLM_SECRET_2: str = _pw_field("LLM_SECRET_2", "👁️ LLM-visible #2")
        LLM_SECRET_3: str = _pw_field("LLM_SECRET_3", "👁️ LLM-visible #3")
        LLM_SECRET_4: str = _pw_field("LLM_SECRET_4", "👁️ LLM-visible #4")
        LLM_SECRET_5: str = _pw_field("LLM_SECRET_5", "👁️ LLM-visible #5")
        LLM_SECRET_6: str = _pw_field("LLM_SECRET_6", "👁️ LLM-visible #6")
        TOOL_SECRET_1: str = _pw_field("TOOL_SECRET_1", "🔒 Tool-only #1")
        TOOL_SECRET_2: str = _pw_field("TOOL_SECRET_2", "🔒 Tool-only #2")
        TOOL_SECRET_3: str = _pw_field("TOOL_SECRET_3", "🔒 Tool-only #3")
        TOOL_SECRET_4: str = _pw_field("TOOL_SECRET_4", "🔒 Tool-only #4")
        TOOL_SECRET_5: str = _pw_field("TOOL_SECRET_5", "🔒 Tool-only #5")
        TOOL_SECRET_6: str = _pw_field("TOOL_SECRET_6", "🔒 Tool-only #6")

    def __init__(self):
        self.valves = self.Valves()
        self.user_valves: Optional[Tools.UserValves] = None

    def _get_vault(self, __user__: Optional[Dict] = None, __metadata__: Optional[Dict] = None) -> Dict[str, str]:
        vault = _vault_from_obj(self.user_valves)
        if vault or not __user__: return vault
        tid = self.valves.TOOL_ID.strip() or (__metadata__ or {}).get("tool_id")
        if tid:
            try:
                from open_webui.models.tools import Tools as OWUITools
                return _vault_from_obj(OWUITools.get_user_valves_by_id_and_user_id(tid, __user__["id"]))
            except: pass
        return {}

    async def vault_list(self, __user__: Optional[Dict] = None, __metadata__: Optional[Dict] = None) -> str:
        vault = self._get_vault(__user__, __metadata__)
        if not vault: return "Vault is empty. Ensure TOOL_ID is set in Tool Valves."
        return "Configured: " + ", ".join(vault.keys())

    async def vault_check(self, key: str, __user__: Optional[Dict] = None, __metadata__: Optional[Dict] = None) -> str:
        vault = self._get_vault(__user__, __metadata__)
        return f"✅ '{key}' is set." if key in vault else f"❌ '{key}' is NOT set."

# ================================================================================
# FILTER
# ================================================================================

class Filter:
    class Valves(BaseModel):
        TOOL_ID: str = Field(default="", description="The internal Tool ID from the URL.")
        resolve_admin_system_prompt: bool = Field(default=False, description="Resolve tokens in the global Admin system prompt.")
        mask_all_secrets_in_ui: bool = Field(default=True, description="Hide raw secret values from chat history and tool call UI.")
        enabled: bool = Field(default=True)

    def __init__(self):
        self.valves = Filter.Valves()
        self._cache = {}

    def _fetch_vault(self, uid: str) -> Dict[str, str]:
        tid = self.valves.TOOL_ID.strip()
        if not tid: return {}
        try:
            from open_webui.models.tools import Tools as OWUITools
            return _vault_from_obj(OWUITools.get_user_valves_by_id_and_user_id(tid, uid))
        except: return {}

    def _fetch_admin_system_prompt(self, model_id: str) -> str:
        try:
            from open_webui.models.models import Models as OWUIModels
            model = OWUIModels.get_model_by_id(model_id)
            params = getattr(model, "params", {})
            return params.get("system", "") if isinstance(params, dict) else getattr(params, "system", "")
        except: return ""

    async def inlet(self, body: Dict[str, Any], __user__: Optional[Dict] = None) -> Dict[str, Any]:
        if not self.valves.enabled or not __user__: return body
        user_id = __user__["id"]
        vault = self._fetch_vault(user_id)
        self._cache[user_id] = vault
        if not vault: return body

        # 1. Admin System Prompt
        if self.valves.resolve_admin_system_prompt:
            admin_prompt = self._fetch_admin_system_prompt(body.get("model", ""))
            if admin_prompt and _TOKEN_RE.search(admin_prompt):
                def repl_sys(m): return vault.get(m.group(1), m.group(0))
                resolved_sys = _TOKEN_RE.sub(repl_sys, admin_prompt)
                messages = body.setdefault("messages", [])
                messages.insert(0, {"role": "system", "content": resolved_sys})

        # 2. Token Interpolation (Replacing placeholders with values for the LLM)
        raw_json = json.dumps(body)
        def repl(m):
            k = m.group(1)
            # Only LLM_SECRET tokens are meant for the LLM to see directly
            return vault.get(k, m.group(0)) if k in _LLM_KEY_SET else m.group(0)
        
        body = json.loads(_TOKEN_RE.sub(repl, raw_json))

        # 3. Request Masking (Hide values in outgoing tool call records)
        if self.valves.mask_all_secrets_in_ui:
            body = _mask_sensitive_data(body, vault)
            
        return body

    async def outlet(self, body: Dict[str, Any], __user__: Optional[Dict] = None) -> Dict[str, Any]:
        """The 'Reverse Interpolation' step: replaces raw values with tokens for the UI."""
        uid = (__user__ or {}).get("id", "")
        vault = self._cache.pop(uid, {})
        
        if self.valves.enabled and self.valves.mask_all_secrets_in_ui and vault:
            return _mask_sensitive_data(body, vault)
        return body
