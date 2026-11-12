#!/bin/zsh
cd -- "${0:A:h}"
if [[ -n "$PACKETLENS_PYTHON" ]]; then
  interpreter="$PACKETLENS_PYTHON"
elif [[ -x /Library/Frameworks/Python.framework/Versions/Current/bin/python3 ]]; then
  interpreter=/Library/Frameworks/Python.framework/Versions/Current/bin/python3
elif [[ -x "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3" ]]; then
  interpreter="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
else
  interpreter=python3
fi
"$interpreter" main.py "$@"
