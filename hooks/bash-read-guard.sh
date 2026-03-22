#!/bin/bash
# Bash Read Guard — blocks shell commands that read sensitive files
# Runs as PreToolUse hook on Bash tool
# Exit codes: 0 = allow, 2 = block
# NOTE: best effort — obfuscated commands (eval, variables, c"a"t) can bypass this

INPUT=$(cat -)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

[ -z "$CMD" ] && exit 0

# Sensitive path patterns
SENSITIVE='(\.ssh/|\.aws/credentials|\.config/gcloud/(application_default|credentials\.db|access_tokens)|\.kube/config|\.netrc|\.docker/config\.json|\.npmrc|\.yarnrc|\.gnupg/private-keys|\.tfstate|service[-_.]account.*\.json)'

# Block commands that read sensitive files
if echo "$CMD" | grep -qiE "(cat|less|more|head|tail|bat|xxd|base64|od|strings|cp|mv|tee|dd|tar|zip)\s.*$SENSITIVE"; then
    echo "BLOCKED: Command attempts to read/copy sensitive credential files." >&2
    exit 2
fi

# Block redirects from sensitive files
if echo "$CMD" | grep -qiE "<\s.*$SENSITIVE"; then
    echo "BLOCKED: Command redirects from sensitive credential file." >&2
    exit 2
fi

# Block opening sensitive files with editors
if echo "$CMD" | grep -qiE "(vim|vi|nano|code|open)\s.*$SENSITIVE"; then
    echo "BLOCKED: Command opens sensitive credential file." >&2
    exit 2
fi

exit 0
