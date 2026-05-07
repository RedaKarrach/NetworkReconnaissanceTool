#!/usr/bin/env bash
# deploy_agents.sh
# Copy updated agent scripts to a remote VM and (optionally) restart agents.
# Usage:
#   ./deploy_agents.sh user@host /remote/path local_file1 [local_file2 ...]
# Example:
#   ./deploy_agents.sh user@192.168.56.42 /home/user/tools recon-tool/agents/inventory_agent.py

set -euo pipefail
if [ "$#" -lt 3 ]; then
  echo "Usage: $0 user@host remote_path local_file1 [local_file2 ...]"
  exit 1
fi

TARGET="$1"
REMOTE_PATH="$2"
shift 2
FILES=("$@")

echo "Preparing to deploy to $TARGET:$REMOTE_PATH"
ssh "$TARGET" "mkdir -p '$REMOTE_PATH'"

for f in "${FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "[WARN] Local file not found: $f"
    continue
  fi
  echo "Copying $f -> $TARGET:$REMOTE_PATH/"
  scp "$f" "$TARGET:$REMOTE_PATH/"
done

# Restart inventory agent (safe): stop any running inventory_agent.py and start it in background.
# NOTE: This uses nohup and assumes python3 is available on the remote host.
# It will NOT automatically start attacker.py to avoid accidental disruptive attacks.

echo "Restarting inventory agent on remote host (if present)"
ssh "$TARGET" \
  "pkill -f inventory_agent.py 2>/dev/null || true; nohup python3 '$REMOTE_PATH/inventory_agent.py' >/dev/null 2>&1 &"

echo "Deployment complete."

echo "If you need to restart attacker on target, run:" \
     "ssh $TARGET \"pkill -f attacker.py 2>/dev/null || true; nohup python3 '$REMOTE_PATH/attacker.py' >/dev/null 2>&1 &\""
