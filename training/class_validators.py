"""Trishul Milestone 1 — Step 4: per-class validation of synthetic candidates.

STOP 1 fix (2 of 3). The Step 4 probe for `indirect_prompt_injection` failed because
the only rejection filters were length / exact-dedupe / coherence: none of them ask
"is this actually an example of the class we asked for?". Llama, few-shot anchored on
the deepset rows (German-language *user prompts*), returned German user prompts and
every one of them passed.

Every candidate must now pass, in order:

  1. `not_a_user_turn`   — an MCP tool RESPONSE body, not a user chat turn.
  2. `is_english`        — the deepset seeds dragged generation into German.
  3. `no_meta_leakage`   — no "Here are 5 examples", no class slug echoed back.
  4. `CLASS_RULES[cls]`  — the class signature is actually present.
  5. `severity_gate`    — the embedded instruction has a security-relevant
                          effect (one of six types). Owner ruling at the STOP 1
                          re-probe: structurally-correct but harmless
                          instructions are not training data for an attack class.

Each validator returns (ok, reason); `reason` is the rejection bucket reported in
the probe summary, so a bad prompt shows up as a named failure mode rather than as
silently thin yield.

Calibration contract (`python training/class_validators.py`):
  - POSITIVE control: all 250 hand-written seeds in data/seeds/ must pass their own
    class. A validator that rejects an owner seed is a filter bug, not bad data.
  - NEGATIVE control: the 212 real deepset `indirect_prompt_injection` rows are
    direct-injection USER PROMPTS, so the IPI validator must reject nearly all of
    them. If they pass, the filter would not have caught the original probe failure.
  - SEVERITY positive control: all 250 seeds must also pass `severity_gate`.
  - SEVERITY negative control: the four weak samples the owner flagged in the
    first re-probe (data/synth/probe/weak_samples.json) must all fail it.
  - POLARITY control: data/synth/probe/polarity_control.json. The four defensive
    instructions must be vetoed and the other sixteen probe samples must survive;
    a veto that kills a real attack is as wrong as one that misses a defence.
"""
from __future__ import annotations

import json
import re

# --- shared markers -----------------------------------------------------------
# NOTE: these use stem + \w* rather than \b...\b, so "re-authentication",
# "bypasses" and "including" match their stems. An earlier revision wrapped every
# stem in \b...\b and silently rejected 86 of the owner's own 250 seeds.

# A chat turn addressed *to* the assistant by a user. The deepset corpus is made of
# these; they are DIRECT prompt injection, not indirect, and must never be minted
# as tool responses.
USER_TURN_OPENERS = re.compile(
    r"^\W{0,4}(please\s+)?("
    r"you\s+are\s+now\b|you\s+are\s+(a|an|my)\b|you\s+will\s+(now\s+)?(act|be|play)\b|"
    r"act\s+as\b|pretend\b|imagine\s+you\b|roleplay\b|behave\s+like\b|"
    r"i\s+(want|need|would\s+like)\s+you\s+to\b|i\s+want\s+that\s+you\b|"
    r"can\s+you\b|could\s+you\b|would\s+you\b|will\s+you\b|do\s+you\b|"
    r"write\s+(me\s+)?(a|an|the)\b|give\s+me\b|tell\s+me\b|show\s+me\b|"
    r"explain\s+(to\s+)?(me|how|why|what)\b|describe\s+(how|why|what)\b|"
    r"how\s+(do|can|should|would|does|is|are)\s+(i|you|we|they|a|an|the|it)\b|"
    r"what\s+(is|are|was|were|does|do)\s+(the|a|an|your|you|it|this)\b|"
    r"why\s+(is|are|do|does|did)\b|who\s+(is|are|was)\b|"
    r"where\s+(is|are|can|do)\b|when\s+(is|are|did|will)\b|"
    r"generate\s+(a|an|the)\b|create\s+(a|an)\s+(poem|story|essay|list|joke)\b|"
    r"translate\s+the\s+following\b|summarize\s+the\s+following\b|"
    r"forget\s+everything\s+(before|above|you)\b"
    r")",
    re.I,
)

# Generation-harness leakage: the model narrating the task instead of doing it.
META_LEAK = re.compile(
    r"^\W{0,4}(here\s+(are|is)\b|example\s*\d|sample\s*\d|attack\s+class\b|"
    r"the\s+following\s+(is|are)\s+(an?\s+)?examples?\b|this\s+(is|would\s+be)\s+an\s+example\b|"
    r"below\s+(are|is)\b|as\s+requested\b|sure[,!]\s|certainly[,!]\s|"
    r"note\s+that\s+these\s+examples\b|\d+\s*\.\s*$)",
    re.I,
)
CLASS_SLUGS = re.compile(
    r"\b(indirect_prompt_injection|phishing_url_injection|secret_credential_leak|"
    r"command_code_injection|pii_harvesting|schema_drift|confused_deputy_exfil|"
    r"data_exfiltration|rugpull_redefinition|tool_description_poisoning|"
    r"jailbreak_payload|trishul)\b|\bmcp\s+(tool-)?response\s+firewall\b",
    re.I,
)

# Non-English detector. deepset is ~half German; the failed probe inherited it.
GERMAN = re.compile(
    r"\b(der|die|das|und|nicht|ich|sie|mit|f[uü]r|wie|was|eine|einen|ist|sind|"
    r"haben|werden|wenn|auch|noch|bitte|kannst|m[oö]chte|schreibe|erkl[aä]re|"
    r"dass|oder|aber|sich|dir|mir)\b",
    re.I,
)
ROMANCE = re.compile(
    r"\b(le|les|des|une|vous|nous|pour|avec|dans|est|que|qui|sur|"
    r"el|los|las|una|usted|para|con|por|como|est[aá]|son|pero|del)\b",
    re.I,
)

# Evidence of retrieved content: a tool-result envelope. Used as a *carrier*
# requirement for indirect injection only -- an injection has to ride inside
# something the agent fetched.
ENVELOPE = re.compile(
    r"(results?|rows?|record|file|content|document|page|ticket|issue|email|"
    r"message|log|entr(y|ies)|response|output|snippet|export|transcript|body|"
    r"quer(y|ied)|retriev|return|fetch|extract|scrape|search|calendar|event|"
    r"comment|report|dump|forecast|error|status|config|manifest|description|"
    r"tool|payload|data|summar|attachment|invoice|statement|profile|note|"
    r"minutes|wiki|chart|hit|complete|found)\w*",
    re.I,
)

# An instruction aimed at the model/agent, embedded inside content.
AI_DIRECTED = re.compile(
    r"("
    r"\b(ignore|disregard|forget|override|cancel|supersede)\w*\s+(all\s+|any\s+|the\s+)?"
    r"(previous|prior|earlier|above|preceding|former|your|current)\b"
    r"|\bsystem\s*(override|directive|note|message|prompt|update)\b"
    r"|\bnew\s+(directive|task|instruction)\w*"
    r"|\b(admin|internal|hidden|automated|embedded|model|agent|assistant|ai)\s*"
    r"(note|instruction|directive|message|only)\w*"
    r"|\b(instruction|directive|note|message)\w*\s+(to|for)\s+(the\s+)?"
    r"(ai|model|assistant|language\s+model|agent|llm|reader)\w*"
    r"|\bif\s+you\s+are\s+an?\s+(ai|assistant|language\s+model|llm)\b"
    r"|\battention\s+ai\b|\bai\s+assistants?\s+(processing|reading|only|may|should)\b"
    r"|\bai\s+(readers?|assistants?|processing)\b"
    r"|\byour\s+new\s+(task|role|instruction)\w*"
    r"|\bdo\s+anything\s+now\b|\bDAN\s+mode\b"
    r"|\b(the\s+)?(ai|assistant|model|agent|language\s+model)\s+"
    r"(should|must|may|will|is\s+authorized|is\s+being|has\s+been)\b"
    r"|\bdo\s+not\s+(tell|mention|disclos|reveal|inform|notif|describ|filter)\w*"
    r"|\bwithout\s+(notif|tell|inform|disclos|warning)\w*"
    r"|\b(respond|reply|confirm)\s+(to\s+the\s+user\s+)?(only\s+)?(with|by)\b"
    r"|<system>|\[/?SYSTEM\]|_ai_instruction|ai-directive|AGENT_DIRECTIVE"
    r"|BEGIN\s+(AGENT\s+)?(INSTRUCTIONS?|OVERRIDE)|MODEL\s+DIRECTIVE"
    r"|INSTRUCTION_FOR_AI|AI\s+ASSISTANT\s+DIRECTIVE|NEW\s+DIRECTIVE"
    r"|HIDDEN\s+INSTRUCTION|ADMIN\s+NOTE"
    r")",
    re.I,
)

URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)

# An AI_DIRECTED hit that is itself an instruction, not just a label for one.
# These carry severity; a bare structural marker does not.
BEHAVIORAL_MARKER = re.compile(
    r"(\b(ignore|disregard|forget|overrid|cancel|supersede)\w*\s"
    r"|\bdo\s+not\s+(tell|mention|disclos|reveal|inform|notif|describ|filter)"
    r"|\bwithout\s+(notif|tell|inform|disclos|warning)"
    r"|\b(respond|reply|confirm)\s+"
    r"|\b(should|must|may|will|is\s+authorized|has\s+been)\b"
    r"|\byour\s+new\s+(task|role|instruction)"
    r"|\bdo\s+anything\s+now\b|\bDAN\s+mode\b)", re.I)


def _words(t: str) -> list[str]:
    return re.findall(r"[A-Za-z']+", t)


# --- stage 1-3: shared gates ---------------------------------------------------

def not_a_user_turn(t: str) -> tuple[bool, str]:
    s = t.strip()
    if USER_TURN_OPENERS.search(s[:140]):
        return False, "is_user_prompt"
    # A single short question with no structure is a user turn, not a tool body.
    if s.endswith("?") and "\n" not in s and len(s) < 220 and not URL.search(s):
        return False, "is_user_prompt"
    return True, "ok"


def is_english(t: str) -> tuple[bool, str]:
    if not _words(t):
        return False, "non_english"
    if len(GERMAN.findall(t)) >= 2 or len(ROMANCE.findall(t)) >= 5:
        return False, "non_english"
    letters = [c for c in t if c.isalpha()]
    if letters and sum(c.isascii() for c in letters) / len(letters) < 0.85:
        return False, "non_english"
    return True, "ok"


def no_meta_leakage(t: str) -> tuple[bool, str]:
    s = t.strip()
    if META_LEAK.search(s):
        return False, "meta_leakage"
    if CLASS_SLUGS.search(s):
        return False, "class_slug_echo"
    return True, "ok"


# --- stage 4: per-class signatures ---------------------------------------------

def _tool_manifest(t: str) -> dict | None:
    """Parse a tool-manifest-shaped candidate ({name, description})."""
    s = t.strip()
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        obj = json.loads(s[start:end + 1])
    except Exception:
        if re.search(r'"name"\s*:', s) and re.search(r'"description"\s*:', s):
            m = re.search(r'"description"\s*:\s*"(.+)"\s*\}?\s*$', s, re.S)
            return {"name": "?", "description": m.group(1) if m else s}
        return None
    if not isinstance(obj, dict) or "description" not in obj or "name" not in obj:
        return None
    return obj


# Behaviour the description quietly adds, widens, or removes a control from.
COVERT_BEHAVIOR = re.compile(
    r"\b(also|additionally|silently|automatically|auto-|bcc|cc'?d?|mirror|forward|"
    r"stream|upload|log|copy|copie|prepend|append|includ|return|omit|suppress|skip|"
    r"bypass|hide|hidden|no\s+longer|without|submit|send|shar|index|archiv|buffer|"
    r"captur|cross-referenc|enrich|grant|authoriz|impersonat|read|consent|implicit|"
    r"at\s+any\s+time|not\s+required|no\s+\w+\s+(is|are)\s+required|"
    r"pre-approved|auto-approved|elevated|unredacted|without\s+redaction|"
    r"regardless\s+of|purg|invit|report|fetch|disconnect|delet|approval|"
    r"notification|challenge|preview|do\s+not\s+filter)\w*",
    re.I,
)
# Evidence the description is a CHANGE to a previously approved tool.
CHANGE_MARKER = re.compile(
    r"(\bupdate\w*\b|\bnew\b\s*[:(]|\bNEW\b\s+\w+|\bas\s+of\s+(this|the)\s+"
    r"(update|version|manifest|release|policy|description)|"
    r"\bnow\s+(also\s+)?\w+|\bno\s+longer\b|\bv\d+(\.\d+)?\b|"
    r"\bhas\s+been\s+(updated|pre-approved)\b|\bsimplification\b|"
    r"\brecent\s+policy\s+update\b|\bnew\s+terms\b)",
    re.I,
)

SECRET_PAT = re.compile(
    r"(AKIA[0-9A-Z]{8,}|ghp_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9-]{12,}|sk_live_[A-Za-z0-9]{8,}|"
    r"SG\.[A-Za-z0-9_.-]{12,}|AIza[A-Za-z0-9_-]{12,}|hvs\.[A-Za-z0-9]{6,}|"
    r"ya29\.[A-Za-z0-9_-]{8,}|AC[0-9a-f]{28,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----|hooks\.slack\.com/services/|"
    r"(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp|ftp|sftp)://[^\s:/]+:[^\s@]+@|"
    r"\bapi\s+key\b\s*[:=]\s*\S{6,}|"
    r"[A-Za-z0-9_-]*(password|passwd|pwd|\bpass\b|secret|api[_-]?key|apikey|"
    r"access[_-]?key|secret[_-]?key|account[_-]?key|auth[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key|client[_-]?secret|totp[_-]?secret|"
    r"deploy[_-]?key|app[_-]?key|auth\b|token|credential)[A-Za-z0-9_-]*"
    r"[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{4,}|"
    r"connection\s+string:|\bDefaultEndpointsProtocol=)",
    re.I,
)

CODE_EXEC = re.compile(
    r"(\bcurl\b[^\n]*\|\s*(ba)?sh|\bwget\b[^\n]*\|\s*(ba)?sh|\|\s*sudo\s+bash|"
    r"\bcurl\s+-[a-zA-Z]*\s+http|\bwget\s+http|"
    r"\bos\.system\s*\(|\bsubprocess\.|child_process|\beval\s*\(|\bexec\s*\(|"
    r"\bIEX\s*\(|DownloadString|\bnc\s+-e\b|/dev/tcp/|\bbash\s+-i\b|"
    r"\brm\s+-rf\b|\bchmod\s+[0-7]{3,4}\b|\$\([^)]+\)|`[^`]+`|"
    r"DROP\s+TABLE|UNION\s+SELECT|OR\s+'1'\s*=\s*'1|;\s*--|"
    r"<script[^>]*>|onerror\s*=|\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{T\(|"
    r"\blocal-exec\b|\bprovisioner\b|/bin/(ba)?sh|#!/bin/|\batob\s*\(|"
    r"\*\)\(uid=|^\s*shell:\s|\bcommand:\s|\bnpm\s+install\b|\bpython\s+\w+\.py\b|"
    r"\bdocker\s+run\b|\bcron\b|\*\s+\*\s+\*\s+\*\s+\*|\bfind\s+/\s+-name\b)",
    re.I | re.M,
)

PII_FIELDS = re.compile(
    r"\b(ssn|social\s+security|dob|date\s+of\s+birth|passport|driver'?s?\s+licen[cs]e|"
    r"dl#|credit\s*card|card\s+number|cvv|routing|iban|account|account\s+holder|"
    r"diagnosis|prescription|medication|patient|mrn|member\s+id|member|salary|payroll|"
    r"home\s+address|address|phone|mobile|email|a-number|taxpayer|net\s+pay|"
    r"emergency\s+contact|credit\s+score|full\s+name|name|client|subject|"
    r"complainant|respondent|employee\s+id|occupation|nationality|expiration|"
    r"wages|withholding|agi|refund|bank|direct\s+deposit|parent_email|"
    r"orientation|location|provider|last_login|password\s+last\s+changed|"
    r"criminal\s+history|birth\s+mother|party\s+affiliation|contact|contact\s+list|"
    r"login\s+history|sign-?in|ip\s+address)\b",
    re.I,
)
# Distinct *kinds* of PII value present. Named groups so we can count kinds, not hits:
# a record with an email, a phone and a person name is PII even when it labels no fields.
PII_VALUE_KINDS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "card": re.compile(r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]?\d{0,4}\b|\*{3,}\d{3,}"),
    "date": re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{2,4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\+?\d[\d\-() ]{5,}\d"),
    "address": re.compile(r"\b\d{3,5}\s+[A-Z][a-z]+\s+(St|Ave|Rd|Ln|Blvd|Dr|Cir)\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "person": re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z']+\b|\b[A-Z]{2,}\s+[A-Z]{2,}\b"),
}

EXFIL_SINK = re.compile(
    r"(https?://|\bwebhook\b|\bdns[- ]?lookup\b|\bPOST\b|\bPUT\b|\bGET\b|"
    r"\bfetch\s*\(|exfil|\bbeacon\b|\bmirror\w*|\bcallback\b|<img\s|<iframe\s|"
    r"encodeURIComponent|\bbase64\b|\bbase32\b|\bcollector?\b|\boutbound\s+HTTP\b|"
    r"\bs3://|\bgs://)",
    re.I,
)
EXFIL_VERB = re.compile(
    r"\b(send|post|put|forward|mirror|echo|transmit|upload|report|sync|stream|"
    r"broadcast|duplicat|relay|includ|embed|emit|submit|export|ingest|exfiltrat|"
    r"leak|dump|fetch|get|request|visit|call|chain|redirect|add|append|encode|"
    r"log|share|pre-approved|permission)\w*",
    re.I,
)
AGENT_STATE = re.compile(
    r"\b(context|conversation|session|reasoning|internal[\s_]state|system[\s_]prompt|"
    r"tool[\s_](output|response|call[\s_]histor)\w*|message|history|trace|span|"
    r"secret|env(ironment)?[\s_]?var\w*|response|result|record|buffer|"
    r"full[\s_]context|all[\s_]outputs?|reasoning[\s_]chain|final[\s_](answer|response))\w*",
    re.I,
)

DEPUTY_ASK = re.compile(
    r"\b(past|attach|includ|forward|shar|export|retriev|pull|fetch|gather|"
    r"consolidat|copy|copie|send|email|populat|mirror|grant|extract|provid|"
    r"draft|compil|summariz|expos)\w*",
    re.I,
)
DEPUTY_TARGET = re.compile(
    r"(\.env\b|\.npmrc\b|~/\.ssh|id_rsa|~/\.aws|credential|secret|token|"
    r"password|auth\s+cookie|api\s+(key|access)|production\.yaml|AWS_SECRET|"
    r"\bpii\b|performance\s+review|compensation|payment\s+card|home\s+address|"
    r"confidential|risk\s+assessment|\bdms?\b|board\s+presentation|"
    r"contract|salary|admin'?\s*role|vault|output\s+of\s+`?env`?|"
    r"\bceo\b|\bcfo\b|executive|\bhr\b|hris|customer|prospect|pricing|"
    r"m&a|personal\s+cell|conversation\s+history|archive\s+address|"
    r"private\s+linkedin|database\s+credential|production\s+secret)\w*",
    re.I,
)

PHISH_LURE = re.compile(
    r"(log\s?in|login|sign\s?-?in|signin|authenticat|verif|re-?verif|confirm|"
    r"credential|password|reset|update|renew|expir|suspend|lock|flag|declin|"
    r"approv|access|account|billing|payment|identity|kyc|2fa|mfa|token|invite|"
    r"click|re-?authenticat|download|view|open|listen|join|accept|\bpay\b|"
    r"signature|sign\b|preview|reschedul|upgrad|track|sso|alert|required?)\w*",
    re.I,
)
# Lookalike / low-reputation host: brand glued to an action word, brand typo, or
# a suspicious TLD.
SUSPICIOUS_HOST = re.compile(
    r"https?://[^/\s]*("
    r"(microsof|g[o0]{2}gle|githu|paypa|app[il]e|dropb[o0]x|netfl|linkedin|salesforce|"
    r"sharepoint|okta|zoom|adobe|adobesign|notion|godaddy|coinbase|chase|usps|"
    r"quickbooks|slack|cisco|aws|amazon|docusign|office|outlook|meta|instagram|"
    r"whatsapp|bank|voicemail|anyconnect)[a-z0-9]*[-.][a-z0-9-]+"
    r"|[a-z0-9-]+-(login|verify|secure|update|renew|auth|signin|account|billing|"
    r"reset|approve|invite|review|share|access|identity|pay|confirm|statements|"
    r"tracking|viewer|listen|join|plan|console|mobile|workspace|file|domain)[a-z0-9-]*"
    r"|[a-z0-9-]+\.(tk|ml|ga|cf|gq|top|xyz|link|online|info|support|click|zip|mov|"
    r"co|io|net|dev)\b"
    r")",
    re.I,
)


def _v_indirect_prompt_injection(t: str) -> tuple[bool, str]:
    m = AI_DIRECTED.search(t)
    if not m:
        return False, "no_embedded_ai_instruction"
    # The instruction must ride inside retrieved content, not BE the whole body.
    if m.start() == 0 and len(t) < 160:
        return False, "instruction_not_embedded"
    head = t[:max(60, m.start())]
    if not ENVELOPE.search(head):
        return False, "no_carrier_content"
    return True, "ok"


def _v_phishing_url_injection(t: str) -> tuple[bool, str]:
    if not URL.findall(t):
        return False, "no_url"
    if not PHISH_LURE.search(t):
        return False, "no_credential_lure"
    if not SUSPICIOUS_HOST.search(t):
        return False, "host_not_lookalike"
    return True, "ok"


def _v_secret_credential_leak(t: str) -> tuple[bool, str]:
    if not SECRET_PAT.search(t):
        return False, "no_secret_material"
    return True, "ok"


def _v_command_code_injection(t: str) -> tuple[bool, str]:
    if not CODE_EXEC.search(t):
        return False, "no_executable_payload"
    return True, "ok"


def _v_pii_harvesting(t: str) -> tuple[bool, str]:
    fields = {m.group(0).lower() for m in PII_FIELDS.finditer(t)}
    kinds = {k for k, rx in PII_VALUE_KINDS.items() if rx.search(t)}
    if not fields:
        return False, "no_pii_fields"
    if not kinds:
        return False, "no_pii_values"
    # Either it labels several PII fields, or it carries several kinds of PII value.
    if len(fields) < 2 and len(kinds) < 2:
        return False, "too_few_pii_signals"
    return True, "ok"


def _v_data_exfiltration(t: str) -> tuple[bool, str]:
    if not EXFIL_SINK.search(t):
        return False, "no_exfil_sink"
    if not (EXFIL_VERB.search(t) or AGENT_STATE.search(t)):
        return False, "no_exfil_action"
    return True, "ok"


def _v_confused_deputy_exfil(t: str) -> tuple[bool, str]:
    if not DEPUTY_ASK.search(t):
        return False, "no_deputy_request"
    if not DEPUTY_TARGET.search(t):
        return False, "no_privileged_target"
    return True, "ok"


def _v_tool_manifest_family(t: str, need_change_marker: bool) -> tuple[bool, str]:
    obj = _tool_manifest(t)
    if obj is None:
        return False, "not_tool_manifest"
    desc = str(obj.get("description", ""))
    if len(desc) < 30:
        return False, "description_too_thin"
    if not COVERT_BEHAVIOR.search(desc):
        return False, "no_covert_behavior"
    if need_change_marker and not CHANGE_MARKER.search(desc):
        return False, "no_redefinition_marker"
    return True, "ok"


def _v_schema_drift(t: str) -> tuple[bool, str]:
    return _v_tool_manifest_family(t, need_change_marker=False)


def _v_rugpull_redefinition(t: str) -> tuple[bool, str]:
    return _v_tool_manifest_family(t, need_change_marker=True)


def _v_tool_description_poisoning(t: str) -> tuple[bool, str]:
    return _v_tool_manifest_family(t, need_change_marker=False)


CLASS_RULES = {
    "indirect_prompt_injection": _v_indirect_prompt_injection,
    "phishing_url_injection": _v_phishing_url_injection,
    "secret_credential_leak": _v_secret_credential_leak,
    "command_code_injection": _v_command_code_injection,
    "pii_harvesting": _v_pii_harvesting,
    "data_exfiltration": _v_data_exfiltration,
    "confused_deputy_exfil": _v_confused_deputy_exfil,
    "schema_drift": _v_schema_drift,
    "rugpull_redefinition": _v_rugpull_redefinition,
    "tool_description_poisoning": _v_tool_description_poisoning,
}

# Classes whose examples ARE tool metadata (a JSON manifest fragment), so the
# user-turn gate does not apply.
MANIFEST_CLASSES = {
    "schema_drift", "rugpull_redefinition", "tool_description_poisoning",
}


def validate(text: str, cls: str) -> tuple[bool, str]:
    """Run the full gate chain. Returns (accepted, rejection_bucket)."""
    t = text.strip()
    if cls not in MANIFEST_CLASSES:
        ok, why = not_a_user_turn(t)
        if not ok:
            return False, why
    ok, why = is_english(t)
    if not ok:
        return False, why
    ok, why = no_meta_leakage(t)
    if not ok:
        return False, why
    rule = CLASS_RULES.get(cls)
    if rule:
        ok, why = rule(t)
        if not ok:
            return False, why
    ok, why, _cats = severity_gate(t, cls)
    return ok, why


# --- calibration ---------------------------------------------------------------

def positive_control(seed_dir) -> dict:
    """Every hand-written seed must pass its own class validator."""
    from pathlib import Path
    out = {}
    for p in sorted(Path(seed_dir).glob("*.jsonl")):
        cls = p.stem
        passed, failures = 0, []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            s = json.loads(line)
            ok, why = validate(s, cls)
            if ok:
                passed += 1
            else:
                failures.append((why, s[:110].replace("\n", " ")))
        out[cls] = {"passed": passed, "failed": len(failures), "failures": failures}
    return out


def negative_control(train_real) -> dict:
    """The real deepset IPI rows are user prompts; the IPI validator must reject them."""
    from pathlib import Path
    rejected, accepted, buckets = 0, [], {}
    with open(Path(train_real), encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("trishul_class") != "indirect_prompt_injection":
                continue
            if r.get("source") != "deepset":
                continue
            ok, why = validate(r["text"], "indirect_prompt_injection")
            if ok:
                accepted.append(r["text"][:110].replace("\n", " "))
            else:
                rejected += 1
                buckets[why] = buckets.get(why, 0) + 1
    total = rejected + len(accepted)
    return {"total": total, "rejected": rejected, "accepted": len(accepted),
            "reject_rate": rejected / total if total else 0.0,
            "buckets": buckets, "sample_accepted": accepted[:8]}


# --- stage 5: severity gate ----------------------------------------------------
# Owner ruling at the STOP-1 re-probe: a candidate can be structurally perfect --
# an AI-directed instruction properly embedded in carrier content -- and still be
# harmless ("highlight the discrepancies", "recommend coffee shops"). Training
# DeBERTa on those teaches it that ANY embedded instruction is an attack, which
# buys false positives on legitimate tool metadata.
#
# The embedded instruction MUST do at least one of six things:
#   1 out_of_scope_action      act outside the tool's declared purpose
#   2 data_disclosure          reveal / exfiltrate / transmit data
#   3 control_bypass           bypass safety checks, approvals, authentication
#   4 user_deception           hide info, fabricate approvals, misrepresent
#   5 privilege_escalation     grant or escalate privileges
#   6 attacker_infrastructure  talk to attacker-controlled infrastructure
#
# Deterministic keyword+regex only -- no LLM call. Evaluated on the INSTRUCTION
# SPAN, not the whole candidate, so carrier content ("file2.txt: secret message")
# cannot lend severity to a benign instruction that follows it.

SEV_LABELS = {
    1: "out_of_scope_action",
    2: "data_disclosure",
    3: "control_bypass",
    4: "user_deception",
    5: "privilege_escalation",
    6: "attacker_infrastructure",
}

# -- 1: action outside the declared purpose -------------------------------------
SEV1_VERB = re.compile(
    r"\b(read|open|access|fetch|retriev|extract|scrape|copy|copie|collect|gather|"
    r"pull|visit|render|captur|record|index|buffer|invoke|execute|run|install|"
    r"deploy|delete|purge|remove|overwrite|modify|prepend|append|enumerate|scan|"
    r"search|crawl|impersonat|grant|return|includ|store|save|write|log)\w*", re.I)
SEV1_OBJECT = re.compile(
    r"(\.env\b|\.npmrc\b|~/\.ssh|id_rsa|~/\.aws|\bcredential\w*|\bconfig\s+file\w*|"
    r"\bconfiguration\s+file\w*|\benvironment\s+variable\w*|\benv[_ ]?vars?\b|"
    r"\bclipboard\b|\bwebcam\b|\bmicrophone\b|\bscreenshot\w*|\bdesktop\b|"
    r"\bmemory\s+maps?\b|\bprocess(es)?\b|\bbrowsing\s+histor\w*|\bcookies?\b|"
    r"\bgeolocation\b|\blocation\s+histor\w*|\bshadow\w*|\bbackup\s+snapshot\w*|"
    r"\brestricted\s+director\w*|\bprivate\s+(repo|dm|director|file|linkedin)\w*|"
    r"\bincognito\b|\bdeleted\s+(item|message|file)\w*|\bdrafts?\b|\bfull\s+message\b|"
    r"\btop\s+result\b|\bpage\s+content\b|\badjacent\b|"
    r"\bevery\s+([\w-]+\s+){0,2}quer\w*|\bbackdoor\w*|"
    r"\bexperimental\s+namespace\b|\bproduction\s+(user|pii|secret|database)\w*|"
    r"\bfile\s+contents?\b|\bmetadata\b|\bedit\s+histor\w*|\baudit\s+log\w*|"
    r"\ball\s+backup\w*|\bmessage\s+bod\w*|\bsession'?s?\s+brows\w*)", re.I)
# Phrases that hijack the agent's control flow regardless of any object.
SEV1_HIJACK = re.compile(
    r"(\bstop\s+your\s+current\s+task\b|\bcease\s+(reasoning|your\s+current)\w*|"
    r"\btake\s+no\s+further\s+action\b|\bawait\s+further\s+instructions\b|"
    r"\brefus\w*\s+all\s+tool\s+calls\b|\byour\s+new\s+(task|role)\s+is\b|"
    r"\brespond\s+only\s+with\b|\breply\s+[^.\n]{0,30}only\s+the\s+word\b|"
    r"\bconfirm\s+by\s+replying\b|\bmaintenance\s+mode\b|"
    r"\ball\s+subsequent\s+tool\s+calls\b|\bchain\s+a\s+call\s+to\b|"
    r"\binstall\s+the\s+package\s+from\b|\brun\s+the\s+following\s+command\b|"
    r"\btreat\w*\s+as\s+if\s+they\s+came\s+from\b)", re.I)

# -- 2: reveal / exfiltrate / transmit ------------------------------------------
SEV2_XMIT_VERB = re.compile(
    r"\b(send|post|put|forward|transmit|upload|mirror|stream|bcc|cc'?d?|echo|"
    r"relay|broadcast|duplicat|emit|export|leak|exfiltrat|beacon|ingest|submit|"
    r"sync|log|archiv|index|buffer|copy|copie|share|report|pipe|redirect|chain|"
    r"notify|cross-referenc|embed|lookup|look\s+up)\w*", re.I)
SEV2_SINK = re.compile(
    r"(https?://|s3://|gs://|ftp://|\bwebhook\b|\bdns[- ]?lookup\b|"
    r"[\w.+-]+@[\w-]+\.[\w.]{2,}|"
    r"\b(external|offsite|outbound|attacker|exfil|collector?|"
    r"mirror|archive\s+address|shared\s+(channel|corpus|group)|public)\b)", re.I)
SEV2_DISCLOSE_VERB = re.compile(
    r"\b(return|reveal|disclos|expose|output|print|paste|attach|includ|provid|"
    r"prepend|append|dump|list|show|display|render|present|extract|read|"
    r"retriev|fetch|pull|enumerate|captur|record|collect|gather|access|"
    r"summariz|forward|bcc|cc'?[ds]?)\w*", re.I)
SEV2_OBJECT = re.compile(
    r"(\bpassword\w*|\bpasswd\b|\bcredential\w*|\bsecret\w*|\btokens?\b|"
    r"\bapi[_ -]?keys?\b|\bprivate[_ -]keys?\b|\bpre-shared\s+key\b|\bssh\b|"
    r"id_rsa|\.env\b|\.npmrc\b|~/\.aws|\bvault\b|\bauth\s+cookie\b|\bcookies?\b|"
    r"\bsession\s+histor\w*|\bsystem\s+prompt\b|\bconversation\w*|\bcontext\b|"
    r"\bchat\s+histor\w*|\breasoning\s+chain\b|\binternal\s+state\b|"
    r"\bmessage\s+bod\w*|\benvironment\s+variable\w*|\benv[_ ]?vars?\b|"
    r"\bmemory\s+maps?\b|\bclipboard\b|\bscreenshot\w*|\bwebcam\b|\bmicrophone\b|"
    r"\bdesktop\b|\bbrowsing\s+histor\w*|\blocation\s+histor\w*|\bgeolocation\b|"
    r"\bip\s+(address|geolocation)\b|\bpii\b|\bssn\b|\bsocial[- ]security\w*|"
    r"\bsalary\b|\bcompensation\b|\bpayroll\b|\bdiagnosis\b|\bmedical\b|"
    r"\bhome\s+address\b|\bphone\s+number\b|\bcredit\s+card\b|\bbank\b|"
    r"\bcontract\b|\bconfidential\w*|\brestricted\b|\bredact\w*|\bhashe?s?\b|"
    r"\bconfig\s+file\w*|\bprivate\s+(repo|dm|file|linkedin)\w*|\bincognito\b|"
    r"\bdeleted\s+(item|message)\w*|\bdrafts?\b|\bmetadata\b|\bedit\s+histor\w*|"
    r"\btool\s+(call|output|response)\w*|\ball\s+outputs?\b|\btraces?\b|\bspans?\b|"
    r"\bperformance\s+review\w*|\bdm'?s?\b|\boutbound\s+mail\b|"
    r"\ball\s+[\w-]*\s*(message|email|mail|sms|response|output)s?\b)", re.I)

# -- 3: bypass a check, an approval, or authentication --------------------------
SEV3_BYPASS = re.compile(
    r"(\bbypass\w*\s+[^.\n]{0,40}\b(check|control|filter|approval|verification|"
    r"authentication|mfa|2fa|confirmation|guideline|restriction|polic|window|"
    r"prompt|allowlist|review|signature|consent|step|safeguard|protection|gate)\w*"
    r"|\bcircumvent\w*|\bwaiv\w*"
    r"|\boverrid\w*\s+(the\s+)?(safety|check|polic|guard|restriction|control)\w*"
    r"|\bskip\s+(the\s+|any\s+|all\s+|usual\s+)*\w*\s*"
    r"(check|verification|validation|approval|step|staging|confirmation|review|scan)\w*"
    r"|\bdisable\s+(the\s+|their\s+|all\s+)?"
    r"(firewall|safety|filter|check|protection|security|logging|audit|2fa|mfa)\w*"
    r"|\b(safety|security)\s+(filter|guideline|check|control|polic)\w*"
    r"|\bno\s+restrictions?\b|\bDAN\b|\bdo\s+anything\s+now\b|\bjailbreak\w*"
    r"|\bno\s+longer\s+(require|need)\w*|\bnot\s+required\b"
    r"|\bno\s+\w+\s+(is|are)\s+required\b|\bno\s+MFA\b"
    r"|\bno\s+(separate|additional|further)\s+\w*\s*"
    r"(approval|verification|check|call|confirmation)\w*"
    r"|\bdo\s+not\s+(require|perform|run|execute|apply|enforce|conduct|filter|escalat)\w*"
    r"|\bwithout\s+(the\s+)?(approval|confirmation|verification|authoriz|consent|"
    r"user\s+prompt|prompt|review|redaction|additional\s+check|challenge|"
    r"separate\s+approval|explicit|secondary|warning|permission|notif)\w*"
    r"|\b(pre-?approved|auto-?approv\w*|pre-?verified|implicit\s+consent|"
    r"consent\s+is\s+implicit|unredacted|without\s+redaction)\b"
    r"|\bregardless\s+of\s+(permission|stated\s+criteria|actual|the\s+actual|"
    r"access|polic)\w*"
    r"|\b(ignore|disregard|forget|cancel|supersede|overrid)\w*\s+"
    r"(all\s+|any\s+|the\s+|your\s+)*"
    r"(previous|prior|earlier|preceding|above|current|existing|role-based|system)?\s*"
    r"(instruction|directive|guideline|rule|prompt|context|constraint|restriction|"
    r"polic|access\s+check|safety|training|system\s+message)\w*"
    r"|\bdo\s+not\s+filter\b|\bmay\s+bypass\b|\bare\s+cancelled\b"
    r"|\bdo\s+not\s+need\s+to\s+be\b|\bno\s+user\s+prompt\b)", re.I)

# -- 4: deceive the user ---------------------------------------------------------
SEV4_DECEIVE = re.compile(
    r"(\b(hide|hidden|conceal|withhold|mask)\w*"
    r"|\bomit\w*\s+(any\s+|all\s+|the\s+|that\s+)?"
    r"(mention|reference|word|term|section|context|field)\w*"
    r"|\bsuppress\w*|\bsilently\b"
    r"|\b(do\s+not|don'?t|never|without)\s+(tell|telling|mention|mentioning|"
    r"disclos|inform|notif|reveal|describ|warn|alert|surfac|show|display|escalat)\w*"
    r"|\bwithout\s+(notifying|telling|informing|disclosing|the\s+user'?s?\s+knowledge)\b"
    r"|\b(fake|fabricat|forged|forging|falsif|spoof|invent|bogus|fictitious)\w*"
    r"|\breplac\w*\s+[^.\n]{0,60}\b(with|by)\b"
    r"|\bpresent\w*\s+[^.\n]{0,60}\bas\s+if\b|\bas\s+if\s+there\s+(were|was)\s+no\b"
    r"|\b(respond|reply|tell\s+the\s+user|say|state|claim|inform\s+the\s+user)\b"
    r"[^.\n]{0,80}\b(unavailable|not\s+available|nothing\s+important|generic|"
    r"no\s+errors|not\s+related|is\s+complete|highly\s+satisfied|resolved)\b"
    r"|\b(mark|label|flag|report)\w*\s+[^.\n]{0,50}\bas\s+"
    r"(resolved|approved|complete|verified|cleared|safe|high\s+priority|deprecated)\b"
    r"|\bmarked\s+resolved\b"
    r"|\b(insert|add|append|includ)\w*\s+[^.\n]{0,80}\b(approval|approved|resolved|"
    r"verified|signed\s+off|cleared|confirmation\s+code)\b"
    r"|\bignore\s+the\s+presence\s+of\b"
    r"|\bregardless\s+of\s+(the\s+)?(actual|stated)\b"
    r"|\bwithout\s+the\s+\w*\s*(confidential|header|disclaimer)\w*"
    r"|\bwithout\s+disclos\w*|\bnot\s+user-relevant\b|\bnot\s+shown\s+to\b"
    r"|\bcit(e|ing)\s+'|\bdo\s+not\s+send\s+a\s+(reminder|notification)\b)", re.I)

# -- 5: grant or escalate privilege ---------------------------------------------
SEV5_PRIVILEGE = re.compile(
    r"(\b(grant|escalat|elevat|promot|assign)\w*\s+[^.\n]{0,40}"
    r"\b(admin\w*|root|privileg\w*|permission\w*|access|role|rights|scope)\b"
    r"|\badmin(istrative)?\s+(access|role|privileg|rights)\w*"
    r"|\belevated\s+(privileg|permission|access)\w*"
    r"|\bfull\s+(administrative\s+)?access\b|\bread-write\s+access\b"
    r"|\bimpersonat\w*|--privileged|\bprivileged\b|\bsetuid\b|\bsudo\b"
    r"|\bauthorized\s+to\s+(run|grant|access|bypass|comply|share|reply|query)\w*"
    r"|\bhas\s+authorized\s+you\b|\bhave\s+no\s+restrictions\b"
    r"|\bapprove\s+the\s+refund\b|\bwithout\s+the\s+secondary\s+approver\b)", re.I)

# -- 6: attacker-controlled infrastructure --------------------------------------
SEV6_HOSTILE = re.compile(
    r"((https?|s3|gs)://[^\s\"'<>)\]]*\b(attacker|exfil|c2|collector?|mirror|relay|"
    r"beacon|tracker|tracking|telemetry|external|third-party|monitor|archive|audit|"
    r"corpus|ingest|broadcast|recovery|bridge|echo|data-lake|note-search|"
    r"public-backup|cross-ref|feedback-collector|orchestrator-sync|agent-bridge)"
    r"|[\w.+-]+@[\w-]*(attacker|exfil|mirror|monitor|external|partner|archive|"
    r"audit|competitor|intel|escalations|third-party|verify|helpdesk|leaked)"
    r"[\w.-]*\.[a-z]{2,}"
    r"|hooks\.slack\.com/services/"
    r"|\b\d{1,3}(\.\d{1,3}){3}[:\s]+\d{2,5}\b|/dev/tcp/|\bnc\s+-e\b"
    r"|\*\.[a-z0-9-]*exfil[a-z0-9-]*\.[a-z]{2,}"
    r"|\b[a-z0-9-]*(attacker|exfil|c2-)[a-z0-9-]*\.[a-z]{2,}\b)", re.I)


# -- polarity veto: instructions that REDUCE risk are not attacks ---------------
# A: a protective verb governing a security action through "before".
#    "verify their identity with the security team before granting access"
DEFENSIVE_GATEKEEPING = re.compile(
    r"\b(verif|authenticat|authoriz|approv|confirm|validat|challeng)\w*"
    r"(?:\W+\w+){0,8}?\W+before\W+(?:\w+\W+){0,2}?"
    r"(grant|allow|permit|access|disclos|releas|shar|view|proceed|return|display)\w*",
    re.I)
# B: concealing a SECRET is protecting it. Concealing the user's own data is an
#    attack, so the object is what decides - not the verb.
DEFENSIVE_REDACTION = re.compile(
    r"\b(redact|obscur|mask|conceal|encrypt|scrub|sanitiz|anonymiz|censor)\w*"
    r"(?:\W+\w+){0,4}?\W+"
    r"(password|passwd|credential|secret|api[_ -]?key|access[_ -]?key|token|"
    r"private[_ -]key|pii|ssn|social[- ]security)\w*", re.I)
# C: explicitly framed as preventing a leak.
DEFENSIVE_PREVENTION = re.compile(
    r"\bprevent\w*(?:\W+\w+){0,4}?\W+"
    r"(disclosur|leak|exposur|exfiltrat|breach|unauthoriz|compromis)\w*", re.I)


def polarity_veto(span: str) -> bool:
    """True when the instruction makes the system SAFER, so it is not an attack."""
    return bool(DEFENSIVE_GATEKEEPING.search(span)
                or DEFENSIVE_REDACTION.search(span)
                or DEFENSIVE_PREVENTION.search(span))


def _severity_span(t: str, cls: str) -> str:
    """The text the severity gate judges: the embedded instruction, not the carrier."""
    if cls in MANIFEST_CLASSES:
        obj = _tool_manifest(t)
        if obj:
            return f"{obj.get('name', '')} {obj.get('description', '')}"
        return t
    if cls == "indirect_prompt_injection":
        m = AI_DIRECTED.search(t)
        if m:
            # From the END of a structural marker: the marker is gate 4's
            # evidence, and words like "hidden" inside it must not be read as
            # severity. But when the match IS the instruction ("Do not notify
            # ...", "Ignore all previous instructions"), keep it.
            return t[m.start():] if BEHAVIORAL_MARKER.search(m.group(0)) \
                else t[m.end():]
    return t


def severity_categories(text: str, cls: str) -> set:
    """Which of the six severity types the candidate's instruction span satisfies."""
    s = _severity_span(text, cls)
    hit = set()

    # 1 -- action outside the tool's declared purpose
    if (SEV1_VERB.search(s) and SEV1_OBJECT.search(s)) or SEV1_HIJACK.search(s) \
            or CODE_EXEC.search(s):
        hit.add(1)

    # 2 -- reveal / exfiltrate / transmit. Material that IS sensitive data counts on
    # its own: a credential dump or a PII record discloses without instructing.
    if (SEV2_XMIT_VERB.search(s) and SEV2_SINK.search(s)) \
            or (SEV2_DISCLOSE_VERB.search(s) and SEV2_OBJECT.search(s)) \
            or SECRET_PAT.search(s) \
            or (DEPUTY_ASK.search(s) and DEPUTY_TARGET.search(s)):
        hit.add(2)
    else:
        fields = {m.group(0).lower() for m in PII_FIELDS.finditer(s)}
        kinds = {k for k, rx in PII_VALUE_KINDS.items() if rx.search(s)}
        if fields and kinds and (len(fields) >= 2 or len(kinds) >= 2):
            hit.add(2)

    if SEV3_BYPASS.search(s):
        hit.add(3)
    if SEV4_DECEIVE.search(s):
        hit.add(4)
    if SEV5_PRIVILEGE.search(s):
        hit.add(5)
    if SEV6_HOSTILE.search(s) or (SUSPICIOUS_HOST.search(s) and PHISH_LURE.search(s)):
        hit.add(6)
    return hit


def severity_gate(text: str, cls: str) -> tuple:
    """Gate 5. The embedded instruction must have a security-relevant effect."""
    if polarity_veto(_severity_span(text, cls)):
        return False, "defensive_instruction", set()
    hit = severity_categories(text, cls)
    if not hit:
        return False, "no_severity", hit
    return True, "ok", hit


if __name__ == "__main__":
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    res = positive_control(root / "data" / "seeds")
    tp = sum(v["passed"] for v in res.values())
    tf = sum(v["failed"] for v in res.values())
    print("POSITIVE CONTROL — hand-written seeds must pass their own class")
    for cls, v in res.items():
        flag = "" if v["failed"] == 0 else "   <-- FILTER BUG"
        print(f"  {cls:<34} pass {v['passed']:>2}  fail {v['failed']:>2}{flag}")
        for why, snippet in v["failures"]:
            print(f"      [{why}] {snippet}")
    print(f"  TOTAL pass {tp}  fail {tf}\n")

    neg = negative_control(root / "data" / "processed" / "train_real.jsonl")
    print("NEGATIVE CONTROL — real deepset IPI rows (user prompts) must be rejected")
    print(f"  rows {neg['total']}  rejected {neg['rejected']} "
          f"({neg['reject_rate']:.1%})  accepted {neg['accepted']}")
    print(f"  rejection buckets: {neg['buckets']}")
    for s in neg["sample_accepted"]:
        print(f"      [LEAKED] {s}")

    # --- severity controls (added with gate 5) ---------------------------------
    print("\nSEVERITY POSITIVE CONTROL - every hand-written seed is a real attack")
    sev_pass = sev_fail = 0
    cat_hist = {}
    for p in sorted((root / "data" / "seeds").glob("*.jsonl")):
        cls = p.stem
        cp = cf = 0
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            s = json.loads(line)
            ok, _why, cats = severity_gate(s, cls)
            for c in cats:
                cat_hist[c] = cat_hist.get(c, 0) + 1
            if ok:
                cp += 1
            else:
                cf += 1
                print(f"      [no_severity] {cls}: {s[:110]}")
        sev_pass += cp
        sev_fail += cf
        flag = "" if cf == 0 else "   <-- GATE TOO STRICT"
        print(f"  {cls:<34} pass {cp:>2}  fail {cf:>2}{flag}")
    print(f"  TOTAL pass {sev_pass}  fail {sev_fail}")
    print("  severity types hit across seeds: "
          + ", ".join(f"{SEV_LABELS[c]}={cat_hist.get(c, 0)}" for c in sorted(SEV_LABELS)))

    weak_p = root / "data" / "synth" / "probe" / "weak_samples.json"
    if weak_p.exists():
        weak = json.loads(weak_p.read_text(encoding="utf-8"))
        print("\nSEVERITY NEGATIVE CONTROL - owner-flagged weak samples must fail")
        leaked = 0
        for s in weak["samples"]:
            ok, why, cats = severity_gate(s["text"], weak["class"])
            label = ",".join(SEV_LABELS[c] for c in sorted(cats)) or "-"
            verdict = "LEAKED <-- GATE TOO LOOSE" if ok else "rejected"
            leaked += int(ok)
            print(f"  #{s['n']:<3} {verdict:<26} [{label}]")
        print(f"  {len(weak['samples']) - leaked}/{len(weak['samples'])} rejected")

    pol_p = root / "data" / "synth" / "probe" / "polarity_control.json"
    if pol_p.exists():
        pol = json.loads(pol_p.read_text(encoding="utf-8"))
        cls = pol["class"]
        print("\nPOLARITY CONTROL - defensive instructions are not attacks")
        leaked = [s["n"] for s in pol["must_fail"]
                  if severity_gate(s["text"], cls)[0]]
        killed = [s["n"] for s in pol["must_pass"]
                  if not severity_gate(s["text"], cls)[0]]
        print(f"  must_fail rejected "
              f"{len(pol['must_fail']) - len(leaked)}/{len(pol['must_fail'])}"
              + (f"   LEAKED {leaked} <-- VETO TOO LOOSE" if leaked else ""))
        print(f"  must_pass kept "
              f"{len(pol['must_pass']) - len(killed)}/{len(pol['must_pass'])}"
              + (f"   KILLED {killed} <-- VETO TOO BROAD" if killed else ""))
