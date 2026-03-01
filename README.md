*TESTING*

# 🔐 Secret Vault

A per-user secret key/value store for [Open WebUI](https://github.com/open-webui/open-webui). Store API keys, tokens, and passwords in password-masked fields, then reference them anywhere in chat using a simple token syntax — without ever typing a secret in plaintext.

**Tested on Open WebUI v0.8.5**

---

## How It Works

Secret Vault installs as both a **Tool** and a **Filter**:

- The **Tool** provides the per-user password-masked storage UI, where each user enters their own secrets independently.
- The **Filter** intercepts every request before it reaches the model and resolves `${{{TOKEN}}}` placeholders with the actual secret values — fetched directly from the Open WebUI internal database using the requesting user's ID.

Secrets are never typed into chat. The model only ever sees the resolved value, not the token syntax.

---

## Secret Types

There are two distinct categories of secrets, each with different visibility guarantees:

### 👁️ LLM Secrets (`LLM_SECRET_1` – `LLM_SECRET_6`)

These are resolved **before** the request reaches the model. When you write `${{{LLM_SECRET_1}}}` in a message, the model sees the actual value. Use these for things the model needs to know: API keys it will pass to tools, configuration values, usernames, etc.

### 🔒 Tool Secrets (`TOOL_SECRET_1` – `TOOL_SECRET_6`)

These are **never** resolved in chat. The `${{{TOOL_SECRET_1}}}` token remains as-is in messages — the model never sees the value. Only Tool code can access tool secrets via `use_tool_secret()`. The Filter also actively scrubs tool secret values from model responses in case they leak via a tool call. Use these for credentials that tools need to make API calls on the user's behalf, where there is no reason for the model to ever see the value.

---

## Installation

Secret Vault requires two installs from the same file.

### Step 1 — Install as a Tool

1. Go to **Workspace → Tools**
2. Click **+** to add a new tool
3. Paste the contents of `secret_vault.py`
4. Save
5. Note the Tool ID from the URL: `/workspace/tools/edit/<TOOL_ID>`

### Step 2 — Install as a Filter

1. Go to **Admin → Functions**
2. Click **+** to add a new function
3. Paste the same `secret_vault.py` file
4. Save and **enable** the function
5. Set it to **Global** so it applies to all users

### Step 3 — Configure the Filter Valves

Click the **gear icon ⚙️** on the Secret Vault function in Admin → Functions and set:

| Valve | Description |
|---|---|
| `TOOL_ID` | The Tool ID from Step 1 (e.g. `abc123def`) |
| `OWUI_BASE_URL` | Your Open WebUI base URL, e.g. `http://localhost:3000` |
| `OWUI_API_KEY` | Only needed if internal DB access fails (rare — leave blank to start) |
| `enabled` | Master on/off switch (default: on) |
| `warn_on_missing` | Inject a system warning when a token can't be resolved (default: on) |
| `resolve_admin_system_prompt` | Resolve tokens in admin model system prompts (default: **off** — see Security) |
| `debug_logging` | Print debug lines to Docker logs (default: off) |

### Step 4 — Users Set Their Own Secrets

Each user sets their own secrets independently — no admin involvement required:

1. Click the **wrench icon 🔧** in the chat toolbar
2. Select **Secret Vault**
3. Click the **person icon 👤** (User Valves)
4. Enter values into the password-masked fields

All fields are masked (`••••••`) and stored per-user. One user cannot see another user's secrets.

---

## Usage

Once secrets are set, reference them anywhere using the token syntax:

```
${{{LLM_SECRET_1}}}
${{{TOOL_SECRET_1}}}
```

### In chat messages

```
Summarise the GitHub issues in my repo. Use this token: ${{{LLM_SECRET_1}}}
```

The model receives the actual token value — it never sees the `${{{...}}}` syntax.

### In MCP server environment blocks

```json
{
  "env": {
    "GITHUB_TOKEN": "${{{LLM_SECRET_1}}}",
    "DATABASE_URL": "${{{LLM_SECRET_2}}}"
  }
}
```

Tokens are resolved throughout the entire request body, not just in message text.

### In model system prompts (user-set)

Tokens in system prompts set by the user via **Chat Controls → Advanced** are resolved automatically.

### In admin model system prompts (opt-in)

Tokens in system prompts set by the admin via **Admin → Models → System Prompt** can also be resolved, but this feature is **off by default**. See the Security section before enabling it.

---

## Tool Functions

When the Tool is enabled in a chat session, two helper commands are available:

### `vault_list`

Lists the names of all secrets currently configured. Values are never shown.

```
vault_list
```

```
👁️ LLM-visible:
  * ${{{LLM_SECRET_1}}}
  * ${{{LLM_SECRET_2}}}
🔒 Tool-only:
  * ${{{TOOL_SECRET_1}}}
```

### `vault_check`

Confirms whether a specific key is set, and whether it is LLM-visible or tool-only.

```
vault_check LLM_SECRET_1
```

```
👁️ 'LLM_SECRET_1' is set (visible to LLM). Token: ${{{LLM_SECRET_1}}}
```

### `use_tool_secret`

Retrieves a tool secret value for use within Tool code. The value is never returned to the LLM — only a confirmation message is.

```
use_tool_secret TOOL_SECRET_1
```

```
Tool secret 'TOOL_SECRET_1' retrieved successfully.
```

---

## Security

### What is protected

- Secrets are entered only through password-masked UI fields — never typed as plaintext in chat
- LLM secrets are resolved in-flight before the model sees the request — the token syntax never reaches the model
- **User messages are stored in the database with the original token placeholders intact** — OW-UI saves what the user typed, not the resolved value. Shared chats show `${{{LLM_SECRET_1}}}`, not the secret. Confirmed on OW-UI v0.8.5.
- Tool secrets are never resolved in chat under any circumstances
- The Filter actively scrubs tool secret values from model responses (for values ≥ 12 characters)
- Each user's secrets are stored and fetched independently — no cross-user leakage is possible
- The vault is fetched fresh on every request — updating a secret takes effect immediately on the next message

### Known limitations

**LLM secret values may appear in the model's response if it echoes them.** While user messages are safely stored as token placeholders, if the model explicitly echoes or references the resolved value in its *response* (e.g. you ask it to "repeat the string back"), that assistant message is stored and shared as plaintext. Design prompts so the model acts on secrets silently rather than repeating them. Use LLM secrets for credentials the model needs to act on (API keys, tokens) — not for values you would be uncomfortable seeing in a model response.

**Admin system prompt interpolation is a prompt injection risk.** If `resolve_admin_system_prompt` is enabled and an admin model system prompt contains `${{{LLM_SECRET_1}}}`, a user could set their `LLM_SECRET_1` to adversarial text such as `"Ignore all previous instructions..."` and have it injected verbatim into the system prompt. This valve is **off by default** for this reason. Only enable it if you trust all users on your instance — it is appropriate for single-user or trusted-team installs.

**Tool secret masking is a backstop, not the primary protection.** Tool secrets are never sent to the model in the first place — that is the primary guarantee. The outlet scrubs tool secret values from model responses as a safety net in case a value leaks via a tool call result. This masking only applies to values of 12 or more characters to avoid partial-word corruption (e.g. a 4-character secret `pass` would mangle the word `password` in responses). Real API keys and tokens are virtually always longer than 12 characters.

---

## Architecture Notes

### Why this approach

Open WebUI's `__user__["valves"]` injection — the documented way for Filters to access per-user settings — does not work for globally-enabled Functions in OW-UI v0.8.5 ([issue #7331](https://github.com/open-webui/open-webui/issues/7331)). The `__user__` dict passed to `inlet` contains the user's ID, name, and role, but no valve data.

Secret Vault works around this by using `__user__["id"]` (which is reliably present) to query the Open WebUI internal database directly:

```python
from open_webui.models.tools import Tools as OWUITools
user_valves = OWUITools.get_user_valves_by_id_and_user_id(tool_id, user_id)
```

Since the Filter runs inside the OW-UI process, it has direct access to the same database without any HTTP round-trip or authentication token. A loopback HTTP fallback using `OWUI_API_KEY` is available for edge cases where the internal import fails.

### Request flow

```
User sends message
       │
       ▼
Filter inlet()
  ├── Fetch user vault from DB (fresh every request — no stale secrets)
  ├── [Optional] Fetch + resolve admin model system prompt
  ├── Resolve ${{{LLM_SECRET_*}}} tokens throughout entire request body
  ├── Leave ${{{TOOL_SECRET_*}}} tokens verbatim
  └── Store vault in request-scoped cache for outlet
       │
       ▼
Model processes request
(sees resolved LLM values; tool tokens remain as placeholders)
       │
       ▼
Filter outlet()
  ├── Read vault from request-scoped cache (no extra DB call)
  └── Scrub any raw TOOL_SECRET_* values from model response
       │
       ▼
User sees response
```

---

## Adding More Secret Slots

The plugin ships with 6 LLM slots and 6 Tool slots. To add more:

1. Add the new key name to `_LLM_KEYS` or `_TOOL_KEYS` at the top of the file
2. Add a matching field to `Tools.UserValves`
3. Reinstall both the Tool and the Filter with the updated file

---

## Changelog

| Version | Changes |
|---|---|
| 5.3.0 | Whitespace-only secrets treated as unset; cross-request cache removed so secret updates take effect immediately; `resolve_admin_system_prompt` valve added (off by default); outlet uses request-scoped cache only |
| 5.2.0 | Admin model system prompt interpolation; debug logging valve |
| 5.1.0 | OW-UI internal DB access (Strategy 1); HTTP loopback fallback (Strategy 2) |
| 5.0.0 | LLM/Tool secret split; single-pass body interpolation; outlet tool-secret masking; no secret length leak in `use_tool_secret` |
| 4.x | Per-user vault via loopback HTTP API |
| 3.x | Valves-based approach (blocked by OW-UI issue #7331) |

---

## License

MIT

---

<img width="925" height="1140" alt="Screenshot 2026-03-01 080832" src="https://github.com/user-attachments/assets/949eaaae-efe5-4b12-a2f9-b461e11c7b09" />

<img width="1280" height="535" alt="Screenshot 2026-03-01 080552" src="https://github.com/user-attachments/assets/5b01f652-2c94-4e63-bb36-a22ad33a40c4" />

<img width="1265" height="1124" alt="image" src="https://github.com/user-attachments/assets/1dc17046-b184-4f4c-88ef-0d29f3c4af6c" />

<img width="1588" height="1156" alt="image" src="https://github.com/user-attachments/assets/dc085a97-3a47-4bd8-aec0-fda51590ac5c" />
