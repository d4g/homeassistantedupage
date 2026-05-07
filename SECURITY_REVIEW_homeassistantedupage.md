# Security Review: `rine77/homeassistantedupage`

**Target:** https://github.com/rine77/homeassistantedupage (HACS custom integration for Home Assistant)
**Commit reviewed:** tip of `main` at clone time (2026-05-07)
**Scope:** the full custom component under `custom_components/homeassistantedupage/` plus CI workflows and dev configs.
**Threat model:** the integration is configured per-HA-instance by the homeowner with their own EduPage credentials. It performs authenticated cloud polling to EduPage. Adversaries to consider: (a) anyone with read access to HA logs / `.storage`, (b) a compromised EduPage server returning malicious data, (c) a compromised dependency on PyPI.

## Severity Summary

| # | Severity | Issue |
|---|----------|-------|
| 1 | **High** | Plaintext password (and PHPSESSID) is logged at `INFO` level by the config flow |
| 2 | **High** | Unbounded `time.sleep` busy-wait in 2FA path can hang the executor indefinitely |
| 3 | **Medium** | Blocking `input()` call in 2FA branch — would deadlock Home Assistant if reached |
| 4 | **Medium** | `unidecode` dependency is unpinned (supply-chain risk); minor: `edupage-api` is pinned but not hash-pinned |
| 5 | **Medium** | Bad-credentials and CAPTCHA errors are silently mapped to `cannot_connect`; user has no signal credentials are wrong |
| 6 | **Low** | Verbose `DEBUG` logging of grades, names, notifications, full coordinator state (PII leakage if debug logs are shared) |
| 7 | **Low** | CI workflows trigger on `pull_request` from forks (read-only HACS/hassfest actions — acceptable, but documented for completeness) |
| 8 | **Low** | Misc. robustness issues (broad `except Exception`, double `async_config_entry_first_refresh`, dead code paths, `print()` to stdout) — not exploitable but should be cleaned up |

---

## Findings

### 1. (HIGH) Password and session ID logged in plaintext

`custom_components/homeassistantedupage/config_flow.py:55`

```python
if user_input is not None:
    _LOGGER.info("User input received: %s", user_input)
```

`user_input` at this point is the dict returned from the config form and contains `CONF_USERNAME`, `CONF_PASSWORD`, and `CONF_SUBDOMAIN`. Home Assistant will write `INFO`-level messages to `home-assistant.log` by default — meaning **a user's EduPage password is persisted to disk in cleartext every time they (re)configure the integration**. Anyone with read access to HA's log file or anyone the user shares a log with for support (a common pattern in HA forums!) gets the password.

The same dict is later mutated to also contain the `PHPSESSID`. Although it is not re-logged after that mutation, the original logging line is already enough to leak the long-lived password.

**Fix:** never log the raw `user_input` dict. If diagnostic output is needed, log only non-secret keys (e.g. `subdomain`, presence flags) at `DEBUG`.

```python
_LOGGER.debug("User submitted config form for subdomain=%s", user_input.get(CONF_SUBDOMAIN))
```

Also remove or scrub the `print("Logged in")` on line 45 — `print()` to stdout from inside HA is noise and bypasses logger filters.

---

### 2. (HIGH) Unbounded busy-wait in 2FA confirmation

`custom_components/homeassistantedupage/config_flow.py:24-28`

```python
if confirmation_method == "1":
    while not second_factor.is_confirmed():
        time.sleep(0.5)
    second_factor.finish()
```

This runs inside an executor thread (`async_add_executor_job`) and **has no timeout**. If the user enables 2FA but never confirms on their device, this thread blocks forever, holding executor capacity and preventing the config flow from ever returning to the UI. Combined with HA's executor pool size, repeated config attempts could starve other integrations.

**Fix:** add a timeout (e.g. 60 s) and surface a `cannot_connect`/custom error to the user:

```python
deadline = time.monotonic() + 60
while not second_factor.is_confirmed():
    if time.monotonic() > deadline:
        raise SecondFactorFailedException("2FA confirmation timed out")
    time.sleep(0.5)
```

A proper async-friendly implementation would use a separate `async_step_2fa` step and return a form, but a timeout is the minimum bar.

---

### 3. (MEDIUM) `input()` in async config flow

`config_flow.py:32-36`

```python
elif confirmation_method == "2":
    code = input("Enter 2FA code (or 'resend' to resend the code): ")
    while code.lower() == "resend":
        second_factor.resend_notifications()
        code = input("Enter 2FA code (or 'resend' to resend the code): ")
    second_factor.finish_with_code(code)
```

Calling `input()` inside Home Assistant has no terminal attached; depending on environment it will either block forever on `stdin.read()` or raise `EOFError`. The code is currently unreachable because `confirmation_method` is hardcoded to `"1"` above, but it's a footgun if anyone changes that constant. Delete this branch or replace it with a real HA flow step.

---

### 4. (MEDIUM) Dependency pinning / supply-chain

`manifest.json`:

```json
"requirements": ["edupage-api==0.12.2", "unidecode"]
```

- `edupage-api` is pinned to a specific version — good.
- `unidecode` is **unpinned**. A future compromised release of `unidecode` on PyPI would be pulled the next time pip resolves dependencies. Pin a known-good version (e.g. `unidecode==1.3.8`).
- HA itself does not support hash-pinning in custom components, but pinning the version is the minimum.

Also note: this integration trusts `edupage-api` entirely for credential handling, TLS verification, and HTTP responses. The reviewer should be aware that the security posture is bounded by that library; a TLS-verification weakness or response-injection bug there would land here unmitigated.

---

### 5. (MEDIUM) Bad-credential / CAPTCHA errors are silently swallowed

`config_flow.py:38-48` catches `BadCredentialsException` and `SecondFactorFailedException` inside the inner `login()` helper and only logs them. Then on line 44, if `api.is_logged_in` is False, it re-raises a new `BadCredentialsException`. The outer `except Exception` (line 85) catches it and sets `errors["base"] = "cannot_connect"` — so a user with the wrong password sees "cannot connect" in the UI and has no idea their credentials were rejected.

`__init__.py` similarly handles `BadCredentialsException` and `CaptchaException` by returning `False` from `async_setup_entry` with no `ConfigEntryAuthFailed` raised. This means the integration won't trigger the standard HA reauth UX; the user has to manually reconfigure.

**Fix:**
- In the config flow, set `errors["base"] = "invalid_auth"` for `BadCredentialsException` and a distinct error for CAPTCHA (`captcha_required` or similar).
- In `async_setup_entry`, raise `ConfigEntryAuthFailed` on credential errors so HA shows the reauth prompt.

---

### 6. (LOW) PII in DEBUG logs

The integration emits `_LOGGER.debug` calls that include:
- Full coordinator return value, which contains grades, student name + ID, teacher names, full timetable, notifications/homework text (`__init__.py:140`, `__init__.py:177`).
- `vars(student)`, `vars(lesson)`, `vars(meal)` (`__init__.py:69`, `calendar.py:122`, `calendar.py:254`).
- Login results (benign — only a boolean).

This is only triggered if the user enables DEBUG, but Home Assistant users routinely paste log excerpts into GitHub issues. Consider:
- Replacing `vars(...)` dumps with a small structured summary.
- Logging only IDs/counts at DEBUG, not free-text content (homework text, comments).

---

### 7. (LOW) CI workflows

`.github/workflows/hacs.yml` and `hassfest.yml` both trigger on `pull_request` (not `pull_request_target`) and use the official `hacs/action` and `home-assistant/actions/hassfest` actions which are read-only validators. No `secrets.*` references exist in either file, and `actions/checkout@v4` is the only checkout action used. No exfiltration vector here. Acceptable.

Recommendation (optional): pin `hacs/action` to a SHA rather than `@main` to avoid running unreviewed action code on every push. Currently:

```yaml
uses: "hacs/action@main"
```

Pin to a tagged release or a commit SHA.

---

### 8. (LOW) Robustness / quality issues

These are not exploitable on their own but indicate places where unexpected state may produce confusing behavior:

- `__init__.py:48` — `e.with_traceback(None)` mutates the exception in place to drop its traceback before logging it. Just log `e` (or use `exc_info=True`).
- `__init__.py:157-170` — `await coordinator.async_config_entry_first_refresh()` is called twice with an `asyncio.sleep(1)` in between. The second call duplicates work and the sleep does not actually serve as a synchronization primitive.
- `__init__.py:33` — `coordinator = None` is set, but the only place it is referenced after a failure path is inside the `try` that itself catches and returns. The dead initialization can be removed.
- `homeassistant_edupage.py:11` — default mutable argument `sessionid=''` is fine for strings but inconsistent with how it's used. Minor.
- Several `except Exception as e: ... return False` blocks (`__init__.py:47, 143, 160`, `homeassistant_edupage.py:44, 53, 69, 78, 87, 95, 103, 111`) silently swallow unexpected errors. Most re-raise as `UpdateFailed`, which is fine; the bare `return False` ones in `async_setup_entry` make debugging hard.
- `config_flow.py:45` — `print("Logged in")`. Remove.
- `subjects.py` is dead code (not referenced anywhere in the integration).
- `.vscode/launch.json` contains a hardcoded path `/home/rine/Projekte/...` — harmless, but reveals developer username.

---

## What's NOT a problem

- **No `eval` / `exec` / `subprocess` / shell invocation** anywhere in the component.
- **No SQL** — no SQLi surface.
- **No HTTP server / web endpoints** exposed by the integration; it is purely a polling client.
- **No file I/O outside HA's normal config-entry storage.**
- **Storing credentials in HA config entries is the standard pattern** for cloud-polling integrations and not specific to this code. HA's `.storage` directory should be protected at the OS level by the user.
- **Unique-IDs include `unidecode`-normalized student name** — purely cosmetic, no injection sink (used as entity unique_id and attribute name).
- **CI workflows** do not have a fork-PR secret-exfil vector.

---

## Recommended Priority

1. **Immediately**: remove the `_LOGGER.info("User input received: %s", user_input)` line (Finding 1). This is the only finding with a clear, real-world data-loss path.
2. **Soon**: add a 2FA timeout (Finding 2) and pin `unidecode` (Finding 4).
3. **Polish**: improve auth-error UX (Finding 5), trim debug logging (Finding 6), pin `hacs/action` (Finding 7), and clean up the rough edges in Finding 8.
