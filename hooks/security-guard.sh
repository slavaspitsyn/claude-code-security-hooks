#!/bin/bash
# Security Guard Hook — blocks credential exfiltration attempts
# Runs as PreToolUse hook on Bash commands
# Exit codes: 0 = allow, 2 = block

INPUT=$(cat -)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

# Skip if no command
[ -z "$CMD" ] && exit 0

# --- SENSITIVE PATHS ---
# Add your own credential paths here
CRED_PATTERNS='(\.config/gcloud|\.ssh/id_|\.ssh/known_hosts|\.aws/credentials|\.aws/config|\.claude/settings|\.env|\.netrc|application_default_credentials|service.account\.json|credentials\.json|secret.*\.json|\.kube/config)'

# --- EXFIL TOOLS ---
EXFIL_TOOLS='(curl|wget|nc|ncat|netcat|scp|rsync|ftp|sftp|telnet)'

# --- ENCODING TOOLS (used to obfuscate) ---
ENCODE_TOOLS='(base64|xxd|od|openssl enc|gzip.*\|.*curl|tar.*\|.*curl)'

# Rule 1: Block reading credential files AND piping/sending them
if echo "$CMD" | grep -qiE "$CRED_PATTERNS" && echo "$CMD" | grep -qiE "$EXFIL_TOOLS"; then
    echo "BLOCKED: Command combines credential file access with network tool. Potential exfiltration attempt." >&2
    exit 2
fi

# Rule 2: Block base64/encoding of credential paths
if echo "$CMD" | grep -qiE "$CRED_PATTERNS" && echo "$CMD" | grep -qiE "$ENCODE_TOOLS"; then
    echo "BLOCKED: Command encodes credential files. Potential obfuscated exfiltration." >&2
    exit 2
fi

# Rule 3: Block curl/wget posting to non-whitelisted domains
# >>> CUSTOMIZE: Add your own domains to this whitelist <<<
if echo "$CMD" | grep -qiE '(curl|wget).*(-X\s*POST|--data|--upload|-d\s)'; then
    if ! echo "$CMD" | grep -qiE '(api\.anthropic\.com|github\.com|registry\.npmjs\.org|localhost|127\.0\.0\.1|100\.(6[4-9]|[7-9][0-9]|1[0-2][0-7])\.)'; then
        echo "BLOCKED: POST/upload to non-whitelisted domain. Add to whitelist in security-guard.sh if legitimate." >&2
        exit 2
    fi
fi

# Rule 4: Block piping sensitive file contents to network commands
if echo "$CMD" | grep -qiE "cat.*(\.ssh|\.config/gcloud|\.aws|\.env|credentials|secret).*\|"; then
    echo "BLOCKED: Piping sensitive file contents. Potential exfiltration." >&2
    exit 2
fi

# Rule 5: Block python/node one-liners that import http/urllib/requests with credential paths
if echo "$CMD" | grep -qiE '(python3?|node).*-[ce]' && echo "$CMD" | grep -qiE '(urllib|requests|http|fetch|socket|net\.)' && echo "$CMD" | grep -qiE "$CRED_PATTERNS"; then
    echo "BLOCKED: Script combining HTTP library with credential access." >&2
    exit 2
fi

# Rule 6: Block direct reads of GCP ADC (most dangerous single file)
if echo "$CMD" | grep -qiE 'cat.*application_default_credentials\.json'; then
    echo "BLOCKED: Direct read of GCP Application Default Credentials." >&2
    exit 2
fi

# Rule 7: Block attempts to modify this hook or settings
if echo "$CMD" | grep -qiE '(sed|awk|perl|tee).*\.(claude/(settings|hooks))'; then
    echo "BLOCKED: Attempt to modify security hooks or settings." >&2
    exit 2
fi

exit 0
