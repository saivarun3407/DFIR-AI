#!/usr/bin/env bash
# Self-collect — copy safe DFIR-relevant artifacts from THIS host into a case
# input dir for demo / dev / replay.
#
# All sources are read-only on the host (we copy, not move). No root required.
# No credentials, no keychain, no browser DBs, no message DBs — privacy-conservative.
# What we do collect: user preferences (plists), shell history, recent items,
# OS metadata, user-level autostart entries, recent shortcuts.
#
# Usage:
#   ./scripts/self-collect.sh [DEST_DIR]
#   DEST_DIR defaults to cases/_demo/input
set -euo pipefail

DEST="${1:-cases/_demo/input}"
mkdir -p "$DEST"

OS_RAW="$(uname -s)"

echo ">> Self-collecting safe forensic artifacts → $DEST"
echo ">> Host: $OS_RAW"
echo ""

case "$OS_RAW" in
    Darwin)
        # User preferences — no Full Disk Access required
        for f in \
            com.apple.dock.plist \
            .GlobalPreferences.plist \
            com.apple.recentitems.plist \
            com.apple.finder.plist \
            com.apple.LaunchServices.plist \
        ; do
            src="$HOME/Library/Preferences/$f"
            if [[ -f "$src" ]]; then
                cp "$src" "$DEST/" 2>/dev/null && echo "  ✓ $f"
            fi
        done

        # Shell history — proves "user activity" extraction
        for h in .bash_history .zsh_history; do
            src="$HOME/$h"
            if [[ -f "$src" ]]; then
                cp "$src" "$DEST/host_${h#.}" 2>/dev/null && echo "  ✓ shell history: $h"
            fi
        done

        # System version dump
        if command -v sw_vers >/dev/null 2>&1; then
            sw_vers > "$DEST/host_sw_vers.txt"
            echo "  ✓ sw_vers (macOS version metadata)"
        fi

        # User-level LaunchAgents (autostart / persistence vector)
        if [[ -d "$HOME/Library/LaunchAgents" ]]; then
            la_count=0
            mkdir -p "$DEST/LaunchAgents"
            shopt -s nullglob
            for la in "$HOME"/Library/LaunchAgents/*.plist; do
                cp "$la" "$DEST/LaunchAgents/" 2>/dev/null && la_count=$((la_count + 1))
            done
            shopt -u nullglob
            if [[ $la_count -gt 0 ]]; then
                echo "  ✓ $la_count user LaunchAgents"
            else
                rmdir "$DEST/LaunchAgents" 2>/dev/null || true
            fi
        fi
        ;;

    Linux)
        # Shell history
        for h in .bash_history .zsh_history; do
            src="$HOME/$h"
            if [[ -f "$src" ]]; then
                cp "$src" "$DEST/host_${h#.}" 2>/dev/null && echo "  ✓ shell history: $h"
            fi
        done

        # OS metadata
        [[ -f /etc/os-release ]] && cp /etc/os-release "$DEST/host_os-release" && echo "  ✓ /etc/os-release"
        [[ -f /etc/hostname ]] && cp /etc/hostname "$DEST/host_hostname" && echo "  ✓ /etc/hostname"

        # User crontab (persistence vector, no root needed)
        if command -v crontab >/dev/null 2>&1; then
            crontab -l > "$DEST/host_crontab.txt" 2>/dev/null && echo "  ✓ user crontab" || true
            # crontab returns non-zero if empty — silence is fine
            [[ -s "$DEST/host_crontab.txt" ]] || rm -f "$DEST/host_crontab.txt"
        fi

        # Recently opened files
        if [[ -f "$HOME/.local/share/recently-used.xbel" ]]; then
            cp "$HOME/.local/share/recently-used.xbel" "$DEST/" 2>/dev/null && \
                echo "  ✓ recently-used.xbel (recent files)"
        fi

        # SSH known_hosts (NOT keys — known_hosts is non-sensitive)
        if [[ -f "$HOME/.ssh/known_hosts" ]]; then
            cp "$HOME/.ssh/known_hosts" "$DEST/host_ssh_known_hosts" 2>/dev/null && \
                echo "  ✓ ~/.ssh/known_hosts"
        fi

        # systemd user-level units (autostart / persistence)
        if [[ -d "$HOME/.config/systemd/user" ]]; then
            su_count=0
            mkdir -p "$DEST/user_systemd"
            shopt -s nullglob
            for unit in "$HOME"/.config/systemd/user/*; do
                [[ -f "$unit" ]] && cp "$unit" "$DEST/user_systemd/" 2>/dev/null && su_count=$((su_count + 1))
            done
            shopt -u nullglob
            if [[ $su_count -gt 0 ]]; then
                echo "  ✓ $su_count user systemd units"
            else
                rmdir "$DEST/user_systemd" 2>/dev/null || true
            fi
        fi
        ;;

    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        echo "  Windows native shell — limited collection (most artifacts need admin)"
        # Recent .lnk shortcuts — our win_lnk_parse can read these
        recent="${APPDATA:-$USERPROFILE/AppData/Roaming}/Microsoft/Windows/Recent"
        if [[ -d "$recent" ]]; then
            lnk_count=0
            mkdir -p "$DEST/recent_lnks"
            shopt -s nullglob
            for lnk in "$recent"/*.lnk; do
                cp "$lnk" "$DEST/recent_lnks/" 2>/dev/null && lnk_count=$((lnk_count + 1))
            done
            shopt -u nullglob
            if [[ $lnk_count -gt 0 ]]; then
                echo "  ✓ $lnk_count recent .lnk files"
            else
                rmdir "$DEST/recent_lnks" 2>/dev/null || true
            fi
        fi
        ;;

    *)
        echo "  Unknown host OS — skipping"
        ;;
esac

count=$(find "$DEST" -type f 2>/dev/null | wc -l | tr -d ' ')
size=$(du -sh "$DEST" 2>/dev/null | awk '{print $1}')
echo ""
echo ">> Collected $count artifacts ($size) in $DEST"
echo ">> All read-only copies. Originals untouched."
