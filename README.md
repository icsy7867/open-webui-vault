*Testing*

# 🔐 Secret Vault — Open WebUI Plugin

A per-user secret key/value store for [Open WebUI](https://github.com/open-webui/open-webui) with password-masked inputs and `${{{TOKEN}}}` interpolation. Secrets are never typed into chat — they live in a masked UI and are injected silently before each request reaches the model.

**Version:** 5.3.0 · **Requires:** Open WebUI ≥ 0.6.x · **License:** MIT

---

## Why This Exists

Open WebUI has no built-in way to give users persistent, private secrets (API keys, tokens, passwords) that can be referenced in chat or MCP tool configurations without appearing as plaintext. This plugin fills that gap.

---

## How It Works

The plugin is a single Python file installed **twice** — once as a Tool, once as a Filter:

- The **Tool** provides password-masked `UserValves` fields where each user stores their own secrets. Values are stored per-user in the OW-UI database and never appear in chat.
- The **Filter** intercepts every request before it reaches the model, fetches the requesting user's secrets directly from the database via OW-UI's internal Python API, and resolves any `${{{TOKEN}}}` placeholders found in the request body.

Because the Filter uses OW-UI's internal DB API (not HTTP), it correctly fetches each user's own secrets regardless of who is making the request.

---

## Secret Types

There are two distinct categories of secret, each with different behaviour:

| Type | Keys | Behaviour |
|---|---|---|
| 👁️ **LLM Secret** | `LLM_SECRET_1` – `LLM_SECRET_6` | Resolved before the request reaches the model. The LLM sees the actual value. |
| 🔒 **Tool Secret** | `TOOL_SECRET_1` – `TOOL_SECRET_6` | **Never** interpolated in chat. Only accessible by Tool code via `use_tool_secret()`. The LLM only ever sees the token placeholder. |

---

## Installation

> The plugin file is installed **twice** — once as a Tool, once as a Function (Filter). Both installs use the same single `secret_vault.py` file.

### Step 1 — Install the Tool

1. Go to **Workspace → Tools → ➕ Add Tool**
2. Paste the contents of `secret_vault.py`
3. Click **Save**
4. Note the Tool ID from the URL: `/workspace/tools/edit/<TOOL_ID>`

### Step 2 — Install the Filter

1. Go to **Admin → Functions → ➕ Add Function**
2. Paste the same `secret_vault.py` file
3. Click **Save**, then toggle it **enabled**
4. Set the scope to **Global** so it applies to all chats

### Step 3 — Configure the Filter Valves

Click the **⚙️ gear icon** on the Function in Admin → Functions and set:

| Valve | Value | Required |
|---|---|---|
| `TOOL_ID` | The ID from Step 1 | ✅ Yes |
| `OWUI_BASE_URL` | Your OW-UI URL, e.g. `http://localhost:3000` | Only if Strategy 1 fails |
| `OWUI_API_KEY` | An API key from Settings → Account → API Keys | Only if Strategy 1 fails |

> **Strategy 1 vs Strategy 2:** The Filter first tries to read secrets directly from OW-UI's internal database (no network call, no API key needed). This works in the vast majority of cases. If it fails for any reason, it falls back to a loopback HTTP call using `OWUI_BASE_URL` and `OWUI_API_KEY`.

### Step 4 — Users Set Their Secrets

Each user sets their own secrets independently via:

**Wrench icon 🔧 in chat → Secret Vault → Person icon 👤 (User Valves)**

All fields render as `••••••••` masked password inputs. The admin cannot see individual users' values.

---

## Usage

Reference any secret using the triple-brace token syntax anywhere in your chat, system prompt, or MCP configuration:

```
${{{LLM_SECRET_1}}}
${{{TOOL_SECRET_1}}}
```

### In Chat Messages

```
Summarise the document at this URL using API key ${{{LLM_SECRET_1}}}
```

The Filter resolves `${{{LLM_SECRET_1}}}` to your actual secret value before the message reaches the model.

### In User System Prompts

Set via Advanced Controls in the chat panel:

```
You are a helpful assistant.
My database connection string is ${{{LLM_SECRET_2}}}.
```

### In the Admin Model System Prompt

Go to **Admin → Settings → Models → [Model] → System Prompt**:

```
Important context:
$API_KEY = ${{{LLM_SECRET_1}}}
```

> ⚠️ This requires the `resolve_admin_system_prompt` Filter valve to be enabled. See [Security Notes](#security-notes) before turning it on.

### In MCP Server Configurations

```json
{
  "env": {
    "GITHUB_TOKEN": "${{{LLM_SECRET_3}}}",
    "DATABASE_URL": "${{{LLM_SECRET_2}}}"
  }
}
```

---

## Filter Valves Reference

Configured via the **⚙️ gear icon** on the Function in Admin → Functions.

| Valve | Default | Description |
|---|---|---|
| `TOOL_ID` | *(empty)* | ID of the Secret Vault Tool install. Find it in the URL when editing the tool. **Required.** |
| `OWUI_BASE_URL` | `http://localhost:3000` | Base URL of your OW-UI instance. Used only for HTTP fallback. |
| `OWUI_API_KEY` | *(empty)* | API key for HTTP fallback. Not needed when internal DB access works. |
| `enabled` | `true` | Master on/off switch for the entire Filter. |
| `warn_on_missing` | `true` | Inject a system-prompt warning when an LLM token can't be resolved. Helps users catch typos in token names. |
| `resolve_admin_system_prompt` | `false` | Resolve tokens in the admin model system prompt. Off by default — see [Security Notes](#security-notes). |
| `debug_logging` | `false` | Print detailed debug output to Docker/server logs. Useful for troubleshooting. Enable temporarily, then turn off. |

---

## Tool Commands

When the Tool is active in a chat, users can ask the model to run these commands:

**`vault_list`** — List all secret key names that are currently set (values never shown).

**`vault_check KEY_NAME`** — Confirm whether a specific key is set, and whether it's LLM-visible or Tool-only.

**`use_tool_secret KEY_NAME`** — For Tool-only secrets: retrieve the value in Tool code without it ever reaching the LLM. Returns a success/failure confirmation only.

---

## Security Notes

### LLM Secrets Are Stored in Chat History

Once an LLM secret is resolved into a message, the actual value is stored in OW-UI's chat history database. Use LLM secrets for values you're comfortable having in database storage (API keys, tokens). For high-rotation passwords, consider Tool secrets instead.

### Tool Secret Masking Has a Minimum Length

Tool secrets are scrubbed from model responses using string replacement. To prevent partial-word corruption (e.g. a secret of `"pass"` would corrupt the word `"password"`), masking only applies to secrets of **12 or more characters**. Real-world secrets (API keys, tokens) are virtually always longer than this — but be aware that very short Tool secret values will not be masked.

### Admin System Prompt Interpolation Is Opt-In

The `resolve_admin_system_prompt` valve is **off by default** for a specific reason: when enabled, a user can set `LLM_SECRET_1` to arbitrary text (including adversarial instructions) which then gets injected verbatim into the admin system prompt. This is a prompt injection risk.

Only enable `resolve_admin_system_prompt` if:
- You trust all users who can set LLM secrets on this instance, **or**
- Your instance is single-user

### No Cross-User Secret Leakage

The vault cache is keyed strictly by user ID. Each request fetches fresh from the database, so secret updates take effect immediately on the next message with no server restart required.

---

## Troubleshooting

**Tokens are not being resolved**

1. Confirm the Filter is enabled and set to Global (Admin → Functions)
2. Confirm `TOOL_ID` is set correctly in the Filter Valves — it must match the ID in the Tool's edit URL exactly
3. Enable `debug_logging` in the Filter Valves, send a test message, then check Docker logs: `docker logs open-webui 2>&1 | grep SECRET_VAULT`
4. The log line `Strategy 1 OK: N keys` confirms secrets were found. If you see `0 keys`, the user hasn't set any secrets yet via the person icon on the Tool.

**Secrets update not taking effect**

The Filter fetches fresh on every request — no restart needed. If you're still seeing old values, confirm you saved the Valves after editing.

**Admin system prompt tokens not resolving**

Ensure `resolve_admin_system_prompt` is toggled on in the Filter Valves (it is off by default).

**Debug logging shows `Tool not found`**

The `TOOL_ID` in the Filter Valves doesn't match the installed Tool. Navigate to **Workspace → Tools → Secret Vault → Edit** and copy the ID from the URL bar.

---

## Known Limitations

- **12 secret slots total** (6 LLM + 6 Tool). Adding more requires editing `_LLM_KEYS` / `_TOOL_KEYS` and adding matching fields to `Tools.UserValves`.
- **OW-UI `__user__["valves"]` injection is broken for globally-enabled Functions** in tested versions (confirmed via GitHub issue [#7331](https://github.com/open-webui/open-webui/issues/7331)). This plugin works around it by reading the database directly.
- **Two system messages** may be sent to the model when `resolve_admin_system_prompt` is enabled — the resolved copy injected by the Filter, and OW-UI's raw copy appended afterwards. Most models handle this correctly, treating the first system message as authoritative.

---

## Development

Run the self-test suite locally (no OW-UI instance required):

```bash
python secret_vault.py
```

All tests mock the OW-UI database calls, so the full logic can be verified without a running server.

---

<img width="925" height="1140" alt="Screenshot 2026-03-01 080832" src="https://github.com/user-attachments/assets/949eaaae-efe5-4b12-a2f9-b461e11c7b09" />

<img width="1280" height="535" alt="Screenshot 2026-03-01 080552" src="https://github.com/user-attachments/assets/5b01f652-2c94-4e63-bb36-a22ad33a40c4" />

<img width="1265" height="1124" alt="image" src="https://github.com/user-attachments/assets/1dc17046-b184-4f4c-88ef-0d29f3c4af6c" />

<img width="1588" height="1156" alt="image" src="https://github.com/user-attachments/assets/dc085a97-3a47-4bd8-aec0-fda51590ac5c" />
