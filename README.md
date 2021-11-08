# wsl2-gpg-agent

## How to use with WSL2
### Prerequisite

```bash
sudo apt install socat iproute2
```

### Installation
1. Download latest version from [release page](https://github.com/AkashiSN/wsl2-gpg-agent/releases/latest) and copy `wsl2-gpg-agent.exe` to your windows directory
    ```bash
    destination="/mnt/c/tools/utils/wsl2-gpg-agent"
    mkdir -p "$destination"
    wget -O "$destination/wsl2-gpg-agent.exe" "https://github.com/AkashiSN/wsl2-gpg-agent/releases/latest/download/wsl2-gpg-agent.exe"
    ```
2. Add one of the following to your shell configuration (for e.g. `.bashrc`, `.zshrc`). For advanced configurations consult the documentation of your shell.



### Bash/Zsh

```bash
wsl2_gpg_agent_bin="/mnt/c/tools/wsl2-gpg-agent/wsl2-gpg-agent.exe"
if test -x "$wsl2_gpg_agent_bin"; then

  export SSH_AUTH_SOCK="$HOME/.gnupg/S.gpg-agent.ssh"
  if ! ss -a | grep -q "$SSH_AUTH_SOCK"; then
    rm -f "$SSH_AUTH_SOCK"
    (setsid nohup socat UNIX-LISTEN:"$SSH_AUTH_SOCK,fork" EXEC:"$wsl2_gpg_agent_bin --ssh" >/dev/null 2>&1 &)
  fi

  export GPG_AGENT_SOCK="$HOME/.gnupg/S.gpg-agent"
  if ! ss -a | grep -q "$GPG_AGENT_SOCK"; then
    rm -rf "$GPG_AGENT_SOCK"
    (setsid nohup socat UNIX-LISTEN:"$GPG_AGENT_SOCK,fork" EXEC:"$wsl2_gpg_agent_bin --gpg S.gpg-agent" >/dev/null 2>&1 &)
  fi

  export GPG_AGENT_EXTRA_SOCK="$HOME/.gnupg/S.gpg-agent.extra"
  if ! ss -a | grep -q "$GPG_AGENT_EXTRA_SOCK"; then
    rm -rf "$GPG_AGENT_EXTRA_SOCK"
    (setsid nohup socat UNIX-LISTEN:"$GPG_AGENT_EXTRA_SOCK,fork" EXEC:"$wsl2_gpg_agent_bin --gpg S.gpg-agent.extra" >/dev/null 2>&1 &)
  fi

else
  echo >&2 "WARNING: $wsl2_gpg_agent_bin is not executable."
fi
unset wsl2_gpg_agent_bin
```