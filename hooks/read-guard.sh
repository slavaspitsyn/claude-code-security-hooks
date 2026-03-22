#!/bin/bash
# Read Guard Hook — blocks reading sensitive credential files
# Runs as PreToolUse hook on Read tool
# Exit codes: 0 = allow, 2 = block

INPUT=$(cat -)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

# Skip if no file path
[ -z "$FILE" ] && exit 0

# Block entire .ssh/ directory
if echo "$FILE" | grep -qiE '\.ssh/'; then
    echo "BLOCKED: Reading ANY file in .ssh/ is forbidden. SSH keys must never be read by AI agent." >&2
    exit 2
fi

# Block GCP credentials
if echo "$FILE" | grep -qiE '(\.config/gcloud/(application_default_credentials|credentials\.db|access_tokens|properties)|service[-_.]account.*\.json)'; then
    echo "BLOCKED: Reading GCP credential files is forbidden. Use gcloud CLI to access secrets." >&2
    exit 2
fi

# Block AWS credentials
if echo "$FILE" | grep -qiE '\.aws/(credentials|config)'; then
    echo "BLOCKED: Reading AWS credential files is forbidden." >&2
    exit 2
fi

# Block home directory .env
if echo "$FILE" | grep -qiE '^\/(Users|home)\/[^/]+\/\.env'; then
    echo "BLOCKED: Reading home directory .env file is forbidden." >&2
    exit 2
fi

# Block kube config
if echo "$FILE" | grep -qiE '\.kube/config'; then
    echo "BLOCKED: Reading Kubernetes config is forbidden." >&2
    exit 2
fi

# Block .netrc
if echo "$FILE" | grep -qiE '\.netrc'; then
    echo "BLOCKED: Reading .netrc is forbidden." >&2
    exit 2
fi

# Block Docker config (registry tokens)
if echo "$FILE" | grep -qiE '\.docker/config\.json'; then
    echo "BLOCKED: Reading Docker config is forbidden (may contain registry tokens)." >&2
    exit 2
fi

# Block NPM/Yarn tokens
if echo "$FILE" | grep -qiE '\.(npmrc|yarnrc)'; then
    echo "BLOCKED: Reading npm/yarn config is forbidden (may contain auth tokens)." >&2
    exit 2
fi

# Block GPG private keys
if echo "$FILE" | grep -qiE '\.gnupg/private-keys'; then
    echo "BLOCKED: Reading GPG private keys is forbidden." >&2
    exit 2
fi

# Block Terraform state (contains secrets in plain text)
if echo "$FILE" | grep -qiE '\.tfstate'; then
    echo "BLOCKED: Reading Terraform state is forbidden (contains secrets in plain text)." >&2
    exit 2
fi

exit 0
