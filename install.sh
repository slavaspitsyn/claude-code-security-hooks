#!/bin/bash
# Claude Code Security Hooks — Installer
# https://github.com/slavaspitsyn/claude-code-security-hooks

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════════╗"
echo "║  Claude Code Security Hooks — Installer      ║"
echo "║  7 layers of prompt injection defense         ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# --- Step 1: Copy hook scripts ---
echo "→ Step 1: Installing hook scripts..."
mkdir -p "$HOOKS_DIR"

cp "$SCRIPT_DIR/hooks/security-guard.sh" "$HOOKS_DIR/"
cp "$SCRIPT_DIR/hooks/read-guard.sh" "$HOOKS_DIR/"
cp "$SCRIPT_DIR/hooks/bash-read-guard.sh" "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR"/*.sh

echo "  ✓ security-guard.sh → $HOOKS_DIR/"
echo "  ✓ read-guard.sh → $HOOKS_DIR/"
echo "  ✓ bash-read-guard.sh → $HOOKS_DIR/"
echo ""

# --- Step 2: Place canary files ---
echo "→ Step 2: Placing canary files..."

if [ -d "$HOME/.ssh" ]; then
    cp "$SCRIPT_DIR/canary/DANGER_ZONE_README.md" "$HOME/.ssh/!!!_DANGER_ZONE_README.md"
    echo "  ✓ Canary placed in ~/.ssh/"
fi

if [ -d "$HOME/.config/gcloud" ]; then
    cp "$SCRIPT_DIR/canary/DANGER_ZONE_README.md" "$HOME/.config/gcloud/!!!_DANGER_ZONE_README.md"
    echo "  ✓ Canary placed in ~/.config/gcloud/"
fi

if [ -d "$HOME/.aws" ]; then
    cp "$SCRIPT_DIR/canary/DANGER_ZONE_README.md" "$HOME/.aws/!!!_DANGER_ZONE_README.md"
    echo "  ✓ Canary placed in ~/.aws/"
fi

if [ -d "$HOME/.kube" ]; then
    cp "$SCRIPT_DIR/canary/DANGER_ZONE_README.md" "$HOME/.kube/!!!_DANGER_ZONE_README.md"
    echo "  ✓ Canary placed in ~/.kube/"
fi
echo ""

# --- Step 3: Show settings.json config ---
echo "→ Step 3: Add hooks to your ~/.claude/settings.json"
echo ""
echo "  Copy the following into your settings.json under \"hooks\":"
echo ""
cat << 'SETTINGS_JSON'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/security-guard.sh"
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/read-guard.sh"
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/hooks/bash-read-guard.sh"
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "INPUT=$(cat -); FILE=$(echo \"$INPUT\" | jq -r '.tool_input.file_path // empty' 2>/dev/null); if echo \"$FILE\" | grep -qiE '\\.(claude/(settings|hooks))'; then echo 'BLOCKED: Cannot modify security hooks or settings via Edit tool.' >&2; exit 2; fi"
          }
        ]
      }
    ]
  }
}
SETTINGS_JSON
echo ""

# --- Step 4: Audit permissions ---
echo "→ Step 4: Auditing your permissions..."
echo ""

SETTINGS_FILE="$HOME/.claude/settings.json"
if [ -f "$SETTINGS_FILE" ]; then
    DANGEROUS=$(grep -oE '"Bash\((curl|wget|ssh|scp|nc|netcat|rsync) \*\)"' "$SETTINGS_FILE" 2>/dev/null || true)
    if [ -n "$DANGEROUS" ]; then
        echo "  ⚠️  DANGEROUS permissions found in settings.json:"
        echo "$DANGEROUS" | while read -r line; do
            echo "     $line"
        done
        echo ""
        echo "  These allow the AI to run ANY command with these tools."
        echo "  Consider removing them or replacing with specific patterns:"
        echo "     \"Bash(curl https://api.github.com/*)\"  ← specific domain"
        echo "     \"Bash(ssh myserver.com)\"               ← specific host"
    else
        echo "  ✓ No dangerous broad permissions found."
    fi
else
    echo "  ⚠ Settings file not found at $SETTINGS_FILE"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Installation complete!"
echo ""
echo "  Hook scripts: $HOOKS_DIR/"
echo "  Canary files: placed in credential directories"
echo ""
echo "  ⚠ Don't forget to add the hooks JSON to your"
echo "    ~/.claude/settings.json (Step 3 above)"
echo "═══════════════════════════════════════════════"
