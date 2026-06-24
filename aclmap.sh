#!/usr/bin/env bash
# aclmap.sh - AD ACL relationship mapper (OSCP-safe, no BloodHound required)
# Maps dangerous ACL relationships between all AD users/groups and OUs using
# dacledit.py (Impacket) and ldapsearch. Only requires one valid domain
# user credential to enumerate ALL object relationships.
#
# Detects:
#   ACL:        GenericAll, ForceChangePassword, AllExtendedRights,
#               GenericWrite, WriteDACL, WriteOwner, FullControl
#               Combined/hex masks that equal GenericAll
#               Group->User and Group->OU inherited paths
#   DCSync:     DS-Replication-Get-Changes-All on domain root
#   Delegation: Constrained Delegation (msDS-AllowedToDelegateTo)
#               Unconstrained Delegation (userAccountControl flag)
#
# Author: Exagon | github.com/Exagon899/scripts
# License: GPLv3

set -o pipefail

# ── colors ────────────────────────────────────────────────────────────────────
RED="\033[1;31m"
ORANGE="\033[0;33m"
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
BOLD="\033[1m"
NC="\033[0m"

# ── banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'BANNER'
    _    ____ _     __  __    _    ____
   / \  / ___| |   |  \/  |  / \  |  _ \
  / _ \| |   | |   | |\/| | / _ \ | |_) |
 / ___ \ |___| |___| |  | |/ ___ \|  __/
/_/   \_\____|_____|_|  |_/_/   \_\_|

   AD ACL Relationship Mapper  |  dacledit-based  |  OSCP-safe
   Maps who can reset/control whom — no BloodHound required
BANNER
echo -e "${NC}"

# ── input ─────────────────────────────────────────────────────────────────────
read -rp "Domain (e.g. thm.corp): " DOMAIN
while [ -z "$DOMAIN" ]; do
    read -rp "Domain is required. Domain (e.g. thm.corp): " DOMAIN
done

read -rp "DC IP: " DCIP
while [ -z "$DCIP" ]; do
    read -rp "DC IP is required. DC IP: " DCIP
done

read -rp "Username (any valid domain user): " USER
while [ -z "$USER" ]; do
    read -rp "Username is required. Username: " USER
done

read -rsp "Password: " PASS
echo
while [ -z "$PASS" ]; do
    read -rsp "Password is required. Password: " PASS
    echo
done

read -rp "Users file (e.g. users.txt): " USERFILE
while [ ! -f "$USERFILE" ]; do
    read -rp "File not found. Users file: " USERFILE
done

echo

# ── build DC base DN from domain ──────────────────────────────────────────────
BASE_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g; s/^/DC=/')

# ── pre-flight checks ─────────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Checking dependencies..."
for cmd in dacledit.py ldapsearch; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}[ERROR]${NC} Required tool not found: $cmd"
        exit 1
    fi
done
echo -e "${GREEN}[OK]${NC} Dependencies found"

echo -e "${CYAN}[*]${NC} Testing credentials against DC..."
TEST=$(ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" "(sAMAccountName=$USER)" sAMAccountName 2>/dev/null | grep "sAMAccountName:")
if [ -z "$TEST" ]; then
    echo -e "${RED}[ERROR]${NC} Authentication failed or DC unreachable"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Authentication successful as $USER@$DOMAIN"
echo

# ── boilerplate trustees to ignore ───────────────────────────────────────────
# Standard AD default trustees — appear on every object by design
BOILERPLATE="Domain Admins\|Enterprise Admins\|Administrators\|Local System\|Creator Owner\|Principal Self\|Authenticated Users\|Everyone\|Pre-Windows 2000\|Enterprise Domain Controllers\|Key Admins\|Enterprise Key Admins\|Account Operators\|Print Operators\|Replicators\|Backup Operators\|RAS and IAS\|Cert Publishers\|DnsAdmins\|UNKNOWN\|Windows Authorization\|Terminal Server\|Protected Users\|IIS_IUSRS\|Network Service\|Service\|Network Configuration\|Event Log Readers\|Performance"

# DCSync boilerplate — always have replication rights by design
DCSYNC_BOILERPLATE="Domain Controllers\|Enterprise Domain Controllers\|Domain Admins\|Enterprise Admins\|Administrators\|Local System\|UNKNOWN\|Protected Users\|Replicators"

# ── classify ACL right ────────────────────────────────────────────────────────
classify_right() {
    local right="$1"
    case "$right" in
        GenericAll|FullControl|COMBINED_GENERICALL)
            echo -e "${RED}GenericAll / FullControl${NC}  ${RED}[CRITICAL - full control, can reset password + more]${NC}" ;;
        User-Force-Change-Password)
            echo -e "${ORANGE}ForceChangePassword${NC}  ${ORANGE}[HIGH - can reset password without knowing current]${NC}" ;;
        AllExtendedRights)
            echo -e "${ORANGE}AllExtendedRights${NC}  ${ORANGE}[HIGH - includes ForceChangePassword + DCSync-like rights]${NC}" ;;
        WriteDACL)
            echo -e "${YELLOW}WriteDACL${NC}  ${YELLOW}[MEDIUM - can modify ACL, grant self GenericAll]${NC}" ;;
        WriteOwner)
            echo -e "${YELLOW}WriteOwner${NC}  ${YELLOW}[MEDIUM - can take ownership, then modify ACL]${NC}" ;;
        GenericWrite)
            echo -e "${GREEN}GenericWrite${NC}  ${GREEN}[LOW-MED - can write attributes, set SPN for Kerberoasting]${NC}" ;;
        *)
            echo -e "${CYAN}$right${NC}" ;;
    esac
}

# ── parse ACE block: extract right from mask+guid, trustee ────────────────────
# Returns "right_name|trustee_name" or empty string if not interesting/boilerplate
# $1 = full dacledit output for one object
parse_aces() {
    local output="$1"

    echo "$output" | awk '
    /ACE\[/ {
        mask = ""; guid = ""; trustee = ""
    }
    /Access mask[[:space:]]*:/ { mask = $0 }
    /Object type \(GUID\)[[:space:]]*:/ { guid = $0 }
    /Trustee \(SID\)[[:space:]]*:/ {
        trustee = $0
        if (mask != "") print mask "|" guid "|" trustee
    }
    ' | while IFS='|' read -r mask guid trustee; do

        # Extract trustee name — strip "Trustee (SID) : " prefix and SID "(S-1-...)" suffix
        trustee_name=$(echo "$trustee" \
            | sed 's/.*Trustee (SID)[[:space:]]*:[[:space:]]*//' \
            | sed 's/[[:space:]]*(S-[0-9-]*)[[:space:]]*$//' \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip empty or boilerplate trustees
        [ -z "$trustee_name" ] && continue
        echo "$trustee_name" | grep -q "$BOILERPLATE" && continue
        # Skip BUILTIN\ prefixed accounts (builtin groups)
        echo "$trustee_name" | grep -qE "^BUILTIN\\\\" && continue
        # Skip machine accounts (ending in $) — DC/computer accounts having OU rights is normal
        echo "$trustee_name" | grep -qE '\$' && continue

        # ── Determine right ────────────────────────────────────────────────────
        right_name=""

        # 1. Check known FullControl hex masks first — most reliable signal
        #    0xf01ff = FullControl (all rights)
        #    0xe01bf = ReadAndExecute+WriteOwner+WriteDACL+AllExtendedRights+ReadProperties+ListChildObjects+DeleteChild
        #    0xf01bd = ReadAndExecute+WriteOwner+WriteDACL+Delete+AllExtendedRights+ReadProperties+ListChildObjects
        #    These hex values appear regardless of how the named rights are listed
        if echo "$mask" | grep -qE "0xf01ff|0xe01bf|0xf01bd"; then
            right_name="FullControl"

        # 2. Combined named mask: WriteDACL + WriteOwner + AllExtendedRights = GenericAll equivalent
        elif echo "$mask" | grep -q "WriteDACL" && \
             echo "$mask" | grep -q "WriteOwner" && \
             echo "$mask" | grep -q "AllExtendedRights"; then
            right_name="COMBINED_GENERICALL"

        # 3. Explicit named rights
        elif echo "$mask" | grep -qE "GenericAll"; then
            right_name="GenericAll"
        elif echo "$mask" | grep -qE "FullControl"; then
            right_name="FullControl"

        # 4. ForceChangePassword: lives in GUID line, mask is just "ControlAccess"
        elif echo "$guid" | grep -q "User-Force-Change-Password"; then
            right_name="User-Force-Change-Password"

        # 5. AllExtendedRights alone (without WriteDACL/WriteOwner — not full GenericAll
        #    but still allows password reset + more)
        elif echo "$mask" | grep -q "AllExtendedRights"; then
            right_name="AllExtendedRights"

        # 6. WriteDACL alone
        elif echo "$mask" | grep -q "WriteDACL"; then
            right_name="WriteDACL"

        # 7. WriteOwner alone
        elif echo "$mask" | grep -q "WriteOwner"; then
            right_name="WriteOwner"

        # 8. GenericWrite
        elif echo "$mask" | grep -q "GenericWrite"; then
            right_name="GenericWrite"
        fi

        [ -z "$right_name" ] && continue

        echo "$right_name|$trustee_name"
    done
}

# ── temp storage ──────────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

RESULTS_FILE="$TMPDIR/results.txt"
DCSYNC_FILE="$TMPDIR/dcsync.txt"
DELEGATION_FILE="$TMPDIR/delegation.txt"
touch "$RESULTS_FILE" "$DCSYNC_FILE" "$DELEGATION_FILE"

# ── step 1: fetch ALL object DNs in one call ──────────────────────────────────
echo -e "${CYAN}[*]${NC} Fetching all object DNs from domain..."

# Users
ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" "(objectClass=user)" distinguishedName sAMAccountName 2>/dev/null \
    > "$TMPDIR/all_dns.txt"

# Computers (can also have delegation/ACL rights)
ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" "(objectClass=computer)" distinguishedName sAMAccountName 2>/dev/null \
    >> "$TMPDIR/all_dns.txt"

# Groups (groups can be trustees on OUs — important for group->user paths)
ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" "(objectClass=group)" distinguishedName sAMAccountName member 2>/dev/null \
    > "$TMPDIR/groups.txt"

echo -e "${GREEN}[OK]${NC} DN lookup complete"

# ── step 2: parse unique OUs ──────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Parsing unique OUs..."

# Parse OUs from user/computer DNs — use sed not awk to handle spaces in OU names
grep "^dn:" "$TMPDIR/all_dns.txt" | sed -n 's/^dn: //p' | \
    sed 's/^CN=[^,]*,//' | sort -u > "$TMPDIR/unique_ous.txt"

# Also parse OUs from group DNs
grep "^dn:" "$TMPDIR/groups.txt" | sed -n 's/^dn: //p' | \
    sed 's/^CN=[^,]*,//' >> "$TMPDIR/unique_ous.txt"

sort -u "$TMPDIR/unique_ous.txt" -o "$TMPDIR/unique_ous.txt"

OU_COUNT=$(wc -l < "$TMPDIR/unique_ous.txt")
USER_COUNT=$(wc -l < "$USERFILE")
TOTAL=$((USER_COUNT + OU_COUNT))

echo -e "${GREEN}[OK]${NC} Found ${BOLD}$USER_COUNT${NC} users and ${BOLD}$OU_COUNT${NC} unique OUs"
echo -e "${CYAN}[*]${NC} Total dacledit calls: ${BOLD}$TOTAL${NC} + domain root + delegation checks"
echo -e "${CYAN}[*]${NC} Estimated time: ~$((TOTAL * 2 / 60)) minutes"
echo

# ── step 3: build group membership map ───────────────────────────────────────
# For each group, store which users from users.txt are members
# This lets us resolve group->OU paths to actual user->OU paths
echo -e "${CYAN}[*]${NC} Building group membership map..."
declare -A GROUP_MEMBERS 2>/dev/null || true

# Parse group memberships from ldapsearch output
# Format: group DN -> list of member DNs
current_group=""
current_group_sam=""
while IFS= read -r line; do
    if echo "$line" | grep -q "^dn:"; then
        current_group=$(echo "$line" | sed 's/^dn: //')
        current_group_sam=""
    elif echo "$line" | grep -q "^sAMAccountName:"; then
        current_group_sam=$(echo "$line" | sed 's/^sAMAccountName: //')
    elif echo "$line" | grep -q "^member:" && [ -n "$current_group_sam" ]; then
        member_dn=$(echo "$line" | sed 's/^member: //')
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            if echo "$member_dn" | grep -qi "CN=$u,"; then
                echo "$current_group_sam|$u" >> "$TMPDIR/group_members.txt"
            fi
        done < "$USERFILE"
    fi
done < "$TMPDIR/groups.txt"
touch "$TMPDIR/group_members.txt"
echo -e "${GREEN}[OK]${NC} Group membership map built"
echo

# ── step 4: check one target object ──────────────────────────────────────────
check_target() {
    local target="$1"
    local target_type="$2"  # "user" or "ou"
    local target_flag=""

    [ "$target_type" = "ou" ] && target_flag="-target-dn" || target_flag="-target"

    local output
    output=$(dacledit.py "$DOMAIN/$USER:$PASS" -dc-ip "$DCIP" \
        $target_flag "$target" -action read 2>/dev/null)

    parse_aces "$output" | while IFS='|' read -r right trustee; do
        # Check if trustee is a group that contains our users
        # If so, expand to user->target relationships
        is_group=0
        if grep -q "^$trustee|" "$TMPDIR/group_members.txt" 2>/dev/null; then
            is_group=1
        fi

        if [ "$is_group" -eq 1 ]; then
            # Expand group to individual users
            grep "^$trustee|" "$TMPDIR/group_members.txt" | cut -d'|' -f2 | while read -r group_user; do
                if [ "$target_type" = "ou" ]; then
                    echo "OU|$group_user|$target|$right|via group: $trustee"
                else
                    echo "USER|$group_user|$target|$right|via group: $trustee"
                fi
            done >> "$RESULTS_FILE"
        else
            # Direct trustee relationship
            if [ "$target_type" = "ou" ]; then
                echo "OU|$trustee|$target|$right|direct"
            else
                echo "USER|$trustee|$target|$right|direct"
            fi
        fi
    done >> "$RESULTS_FILE"
}

# ── step 5: scan all users ────────────────────────────────────────────────────
echo -e "${BOLD}[Phase 1/3]${NC} Scanning user objects for ACL relationships..."
tput sc
COUNT=0
while IFS= read -r target_user; do
    [ -z "$target_user" ] && continue
    ((++COUNT)) || true
    tput rc; tput el
    printf "${CYAN}[*]${NC} [$COUNT/$USER_COUNT] Checking user: $target_user"
    check_target "$target_user" "user" >/dev/null 2>/dev/null
done < "$USERFILE"
tput rc; tput el
echo -e "${GREEN}[OK]${NC} User scan complete"
echo

# ── step 6: scan all OUs ─────────────────────────────────────────────────────
echo -e "${BOLD}[Phase 2/3]${NC} Scanning OU objects for ACL relationships..."
tput sc
COUNT=0
while IFS= read -r target_ou; do
    [ -z "$target_ou" ] && continue
    ((++COUNT)) || true
    tput rc; tput el
    printf "${CYAN}[*]${NC} [$COUNT/$OU_COUNT] Checking OU: $(echo "$target_ou" | cut -c1-80)"
    check_target "$target_ou" "ou" >/dev/null 2>/dev/null
done < "$TMPDIR/unique_ous.txt"
tput rc; tput el
echo -e "${GREEN}[OK]${NC} OU scan complete"
echo

# ── step 7: DCSync rights check ───────────────────────────────────────────────
echo -e "${BOLD}[Phase 3/3]${NC} Checking DCSync rights and delegation..."

DCSYNC_OUTPUT=$(dacledit.py "$DOMAIN/$USER:$PASS" -dc-ip "$DCIP" \
    -target-dn "$BASE_DN" -action read 2>/dev/null)

# DCSync requires DS-Replication-Get-Changes-All (GUID: 1131f6ad)
# Also catch AllExtendedRights and FullControl which include replication rights
echo "$DCSYNC_OUTPUT" | awk '
/ACE\[/ { mask = ""; guid = ""; trustee = "" }
/Access mask[[:space:]]*:/ { mask = $0 }
/Object type \(GUID\)[[:space:]]*:/ { guid = $0 }
/Trustee \(SID\)[[:space:]]*:/ { trustee = $0; if (mask != "") print mask "|" guid "|" trustee }
' | while IFS='|' read -r mask guid trustee; do
    trustee_name=$(echo "$trustee" \
        | sed 's/.*Trustee (SID)[[:space:]]*:[[:space:]]*//' \
        | sed 's/[[:space:]]*(S-[0-9-]*)[[:space:]]*$//' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    [ -z "$trustee_name" ] && continue
    echo "$trustee_name" | grep -q "$DCSYNC_BOILERPLATE" && continue
    echo "$trustee_name" | grep -qE "^BUILTIN\\\\" && continue
    echo "$trustee_name" | grep -qE '\$' && continue

    # DCSync-specific GUID OR AllExtendedRights OR FullControl hex masks
    if echo "$guid" | grep -q "1131f6ad\|1131f6aa\|DS-Replication"; then
        echo "$trustee_name|DCSync-specific" >> "$DCSYNC_FILE"
    elif echo "$mask" | grep -qE "AllExtendedRights|0xf01ff|0xe01bf|0xf01bd"; then
        echo "$trustee_name|AllExtendedRights" >> "$DCSYNC_FILE"
    fi
done

# ── step 8: delegation checks ─────────────────────────────────────────────────
# Constrained delegation
ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" "(msDS-AllowedToDelegateTo=*)" \
    sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null | \
    awk '
    /^sAMAccountName:/ { acct = $2 }
    /^msDS-AllowedToDelegateTo:/ { print "CONSTRAINED|" acct "|" $2 }
    ' >> "$DELEGATION_FILE"

# Unconstrained delegation — exclude DCs (primaryGroupID 516=DC, 521=RODC)
ldapsearch -x -H "ldap://$DCIP" -D "$USER@$DOMAIN" -w "$PASS" \
    -b "$BASE_DN" \
    "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))" \
    sAMAccountName 2>/dev/null | grep "^sAMAccountName:" | \
    awk '{print "UNCONSTRAINED|" $2}' >> "$DELEGATION_FILE"

echo -e "${GREEN}[OK]${NC} DCSync and delegation checks complete"
echo

# ── step 9: display results ───────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}           ACL RELATIONSHIP MAP - RESULTS               ${NC}"
echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${NC}"
echo

# ── Build deduplicated unified ACL result set ─────────────────────────────────
# Track seen trustee→target pairs to avoid duplicates across direct+OU results
SEEN_FILE="$TMPDIR/seen_pairs.txt"
touch "$SEEN_FILE"

# ── ACL: direct user→user relationships ──────────────────────────────────────
USER_RESULTS=$(grep "^USER|" "$RESULTS_FILE" | sort -u)
OU_RESULTS=$(grep "^OU|" "$RESULTS_FILE" | sort -u)

HAS_DIRECT_RESULTS=0
if [ -n "$USER_RESULTS" ]; then
    # Check if any non-duplicate results exist
    while IFS='|' read -r type trustee target right via; do
        pair="$trustee|$target"
        if ! grep -qF "$pair" "$SEEN_FILE" 2>/dev/null; then
            HAS_DIRECT_RESULTS=1
            break
        fi
    done <<< "$USER_RESULTS"
fi

if [ "$HAS_DIRECT_RESULTS" -eq 1 ]; then
    echo -e "${BOLD}── Direct ACL relationships ────────────────────────────${NC}"
    echo
    echo "$USER_RESULTS" | while IFS='|' read -r type trustee target right via; do
        pair="$trustee|$target"
        grep -qF "$pair" "$SEEN_FILE" 2>/dev/null && continue
        echo "$pair" >> "$SEEN_FILE"
        if [ "$via" = "direct" ]; then
            echo -e "  ${BOLD}$trustee${NC}  ${CYAN}→${NC}  ${BOLD}$target${NC}"
        else
            echo -e "  ${BOLD}$trustee${NC}  ${CYAN}→${NC}  ${BOLD}$target${NC}  ${MAGENTA}($via)${NC}"
        fi
        echo -e "  └─ $(classify_right "$right")"
        echo
    done
fi

# ── ACL: ou→user (expanded, deduplicated against direct results) ──────────────
HAS_OU_RESULTS=0

if [ -n "$OU_RESULTS" ]; then
    # Pre-check if any non-duplicate OU results exist after expansion
    while IFS='|' read -r type trustee target_ou right via; do
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            user_dn=$(grep -i "sAMAccountName: $u" "$TMPDIR/all_dns.txt" -B 10 \
                | grep "^dn:" | sed -n 's/^dn: //p' | tail -1)
            if [ -n "$user_dn" ]; then
                user_ou=$(echo "$user_dn" | sed 's/^CN=[^,]*,//')
                if [ "$user_ou" = "$target_ou" ]; then
                    pair="$trustee|$u"
                    if ! grep -qF "$pair" "$SEEN_FILE" 2>/dev/null; then
                        HAS_OU_RESULTS=1
                        break 2
                    fi
                fi
            fi
        done < "$USERFILE"
    done <<< "$OU_RESULTS"
fi

if [ "$HAS_OU_RESULTS" -eq 1 ]; then
    echo -e "${BOLD}── OU-inherited ACL relationships ──────────────────────${NC}"
    echo

    echo "$OU_RESULTS" | while IFS='|' read -r type trustee target_ou right via; do
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            user_dn=$(grep -i "sAMAccountName: $u" "$TMPDIR/all_dns.txt" -B 10 \
                | grep "^dn:" | sed -n 's/^dn: //p' | tail -1)
            if [ -n "$user_dn" ]; then
                user_ou=$(echo "$user_dn" | sed 's/^CN=[^,]*,//')
                if [ "$user_ou" = "$target_ou" ]; then
                    pair="$trustee|$u"
                    grep -qF "$pair" "$SEEN_FILE" 2>/dev/null && continue
                    echo "$pair" >> "$SEEN_FILE"
                    ou_short=$(echo "$target_ou" | sed 's/,DC=.*//' | cut -c1-60)
                    if [ "$via" = "direct" ]; then
                        echo -e "  ${BOLD}$trustee${NC}  ${CYAN}→${NC}  ${BOLD}$u${NC}  ${MAGENTA}(via OU: $ou_short)${NC}"
                    else
                        echo -e "  ${BOLD}$trustee${NC}  ${CYAN}→${NC}  ${BOLD}$u${NC}  ${MAGENTA}(via OU: $ou_short | $via)${NC}"
                    fi
                    echo -e "  └─ $(classify_right "$right")"
                    echo
                fi
            fi
        done < "$USERFILE"
    done
fi

if [ ! -s "$RESULTS_FILE" ]; then
    echo -e "${YELLOW}[!]${NC} No interesting ACL relationships found."
fi

# ── DCSync results ────────────────────────────────────────────────────────────
if [ -s "$DCSYNC_FILE" ]; then
    echo -e "${BOLD}── DCSync rights (non-default accounts) ────────────────${NC}"
    echo
    sort -u "$DCSYNC_FILE" | while IFS='|' read -r account right_type; do
        echo -e "  ${BOLD}$account${NC}"
        echo -e "  └─ ${RED}DCSync rights on domain root${NC}  ${RED}[CRITICAL - can dump all hashes via secretsdump.py]${NC}"
        echo -e "     ${CYAN}Right type: $right_type${NC}"
        echo
    done
fi

# ── delegation results ────────────────────────────────────────────────────────
CONSTRAINED=$(grep "^CONSTRAINED|" "$DELEGATION_FILE" | sort -u)
UNCONSTRAINED=$(grep "^UNCONSTRAINED|" "$DELEGATION_FILE" | sort -u)

if [ -n "$CONSTRAINED" ]; then
    echo -e "${BOLD}── Constrained Delegation accounts ─────────────────────${NC}"
    echo
    echo "$CONSTRAINED" | awk -F'|' '{print $2}' | sort -u | while read -r acct; do
        echo -e "  ${BOLD}$acct${NC}"
        echo -e "  └─ ${ORANGE}Constrained Delegation${NC}  ${ORANGE}[HIGH - can impersonate any user to:]${NC}"
        echo "$CONSTRAINED" | awk -F'|' -v a="$acct" '$2==a {print "       " $3}'
        echo
    done
fi

if [ -n "$UNCONSTRAINED" ]; then
    echo -e "${BOLD}── Unconstrained Delegation accounts ───────────────────${NC}"
    echo
    echo "$UNCONSTRAINED" | while IFS='|' read -r type acct; do
        echo -e "  ${BOLD}$acct${NC}"
        echo -e "  └─ ${RED}Unconstrained Delegation${NC}  ${RED}[CRITICAL - captures TGTs of any connecting user]${NC}"
        echo
    done
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${NC}"
ACL_COUNT=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
DCSYNC_COUNT=$(sort -u "$DCSYNC_FILE" 2>/dev/null | wc -l || echo 0)
DELEG_COUNT=$(wc -l < "$DELEGATION_FILE" 2>/dev/null || echo 0)
echo -e "${GREEN}[DONE]${NC} ACL: ${BOLD}$ACL_COUNT${NC} | DCSync: ${BOLD}$DCSYNC_COUNT${NC} | Delegation: ${BOLD}$DELEG_COUNT${NC}"
echo
echo -e "${YELLOW}[TIP]${NC}  Exploit ForceChangePassword/GenericAll:"
echo -e "       rpcclient -U '${DOMAIN}/<trustee>%<pass>' $DCIP -c 'setuserinfo2 <target> 23 \"NewPass123!\"'"
echo -e "${YELLOW}[TIP]${NC}  Exploit DCSync:"
echo -e "       secretsdump.py ${DOMAIN}/<account>:<pass>@$DCIP"
echo -e "${YELLOW}[TIP]${NC}  Exploit Constrained Delegation:"
echo -e "       getST.py -spn <service> -impersonate Administrator ${DOMAIN}/<account>:<pass> -dc-ip $DCIP"
echo
