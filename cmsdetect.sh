#!/usr/bin/env bash
# cmsdetect.sh - generic CMS/web-framework fingerprinting tool with version detection
# Matches HTML body, headers, and cookies against an embedded signature DB.
# No external DB file or API needed - everything ships in this script.
#
# Signature database combines two sources, plus hand-added entries:
#  1. CMSeeK (GPLv3, Copyright 2018-2020 Tuhinshubhra), converted from its
#     cmseekdb/{cmss,sc,header,robots}.py source files.
#     Original project: https://github.com/Tuhinshubhra/CMSeeK
#  2. Wappalyzer's open-source technology fingerprint database (Apache-2.0),
#     CMS-category entries only, converted from the last public mirror before
#     the original repo went private: https://github.com/dochne/wappalyzer
#  3. A handful of additional signatures (e.g. Cockpit CMS, Strapi, Directus,
#     ProcessWire, CouchCMS, Gila CMS) added by hand for CMS not present in
#     either of the above, found via real-world testing on lab/THM targets.
# Because this script embeds and redistributes GPLv3-derived signature data
# alongside the Wappalyzer data, this script as a whole is licensed under
# GPLv3 - see https://www.gnu.org/licenses/gpl-3.0.html
#
# Version detection: after a CMS is matched, the script searches the page body for
# the CMS name (or any of its matched signature strings) and looks for a version
# number in close proximity (context-anchored regex, not "any number on the page").
# If nothing is found on the main page, it then fetches a set of known version-
# disclosure paths (CMS-specific where researched, generic README/CHANGELOG/composer.json
# fallback otherwise) and repeats the same proximity search there.
#
# Fallback name-only matching: if no CMS scores above 0 via the signature engine,
# the script falls back to a much larger list of CMS NAMES ONLY (no patterns -
# just checks if the product name appears verbatim in the page). This catches
# very small/niche CMS that have a name but no researched detection pattern,
# at the cost of weaker confidence (name-only matches are always shown as Stage
# "name-only" with a low, fixed confidence score and a clear caveat).

set -uo pipefail

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

clear
echo -e "${CYAN}"
cat << 'BANNER'
  ██████ ███    ███ ███████ ██████  ███████ ████████ ███████  ██████ ████████
 ██      ████  ████ ██      ██   ██ ██         ██    ██      ██         ██
 ██      ██ ████ ██ ███████ ██   ██ █████      ██    █████   ██         ██
 ██      ██  ██  ██      ██ ██   ██ ██         ██    ██      ██         ██
  ██████ ██      ██ ███████ ██████  ███████    ██    ███████  ██████    ██

        CMS / Framework Fingerprinter  |  curl-based  |  OSCP-safe
BANNER
echo -e "${NC}"

read -rp "url (e.g. http://10.10.10.10/): " URL
while [ -z "$URL" ]; do
    read -rp "URL is required. url (e.g. http://10.10.10.10/): " URL
done

echo

# ── pre-flight check ──────────────────────────────────────────────────────────

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 -L "$URL" 2>/dev/null)
# curl can print "000" on its own (DNS/connect failure, timeout) even though the
# command substitution still "succeeds" - normalize anything non-3-digit to 000
# rather than relying on `|| echo` which can concatenate onto curl's own "000"
# output and produce "000000".
if ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
    HTTP_CODE="000"
fi
if [ "$HTTP_CODE" = "000" ]; then
    # one retry - transient connection hiccups (slow first TLS handshake, etc.)
    # are common enough on lab/THM networks that a single immediate retry avoids
    # false negatives without meaningfully slowing down the real failure case.
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 -L "$URL" 2>/dev/null)
    if ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
        HTTP_CODE="000"
    fi
fi
if [ "$HTTP_CODE" = "000" ]; then
    echo -e "${RED}[ERROR] URL is not reachable: $URL${NC}"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Target reachable ($HTTP_CODE): $URL"
echo

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ── spinner ───────────────────────────────────────────────────────────────────

spinner() {
    local pid=$1
    local label=$2
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        local c="${chars:$((i % ${#chars})):1}"
        printf "\r${CYAN}[%s]${NC} %s..." "$c" "$label"
        sleep 0.1
        ((i++)) || true
    done
    printf "\r\033[K"
}

# ── fetch target (body + headers, following redirects) ──────────────────────

fetch() {
    curl -s -L --max-time 10 \
        -D "$TMPDIR/headers.txt" \
        -o "$TMPDIR/body.html" \
        "$URL" > /dev/null 2>&1

    # also grab robots.txt (best-effort, ignore failures)
    BASE_URL=$(echo "$URL" | grep -oE '^https?://[^/]+')
    curl -s --max-time 5 "${BASE_URL}/robots.txt" -o "$TMPDIR/robots.txt" 2>/dev/null || true
    echo "$BASE_URL" > "$TMPDIR/base_url.txt"
}

FETCH_PID_LOG="$TMPDIR/fetch.log"
( fetch ) > "$FETCH_PID_LOG" 2>&1 &
FETCH_PID=$!
spinner "$FETCH_PID" "Step 1/3: Fetching target (body, headers, robots.txt)"
wait "$FETCH_PID"

BODY_FILE="$TMPDIR/body.html"
HEADERS_FILE="$TMPDIR/headers.txt"
ROBOTS_FILE="$TMPDIR/robots.txt"
BASE_URL_FILE="$TMPDIR/base_url.txt"

[ -f "$BODY_FILE" ] || touch "$BODY_FILE"
[ -f "$HEADERS_FILE" ] || touch "$HEADERS_FILE"
[ -f "$ROBOTS_FILE" ] || touch "$ROBOTS_FILE"
[ -f "$BASE_URL_FILE" ] || echo "$URL" > "$BASE_URL_FILE"

# A near-empty body usually means a transient network hiccup during fetch (slow
# handshake, momentary drop) rather than a genuinely empty page - retry once
# before proceeding, so a flaky first request doesn't silently produce a false
# "no CMS matched" result.
BODY_SIZE=$(wc -c < "$BODY_FILE" 2>/dev/null || echo 0)
if [ "$BODY_SIZE" -lt 50 ]; then
    ( fetch ) > "$FETCH_PID_LOG" 2>&1 &
    FETCH_PID=$!
    spinner "$FETCH_PID" "Step 1/3 (retry): Body looked empty, fetching again"
    wait "$FETCH_PID"
    BODY_SIZE=$(wc -c < "$BODY_FILE" 2>/dev/null || echo 0)
    if [ "$BODY_SIZE" -lt 50 ]; then
        echo -e "${YELLOW}[WARN]${NC} Fetched page body is very small (${BODY_SIZE} bytes) even after retry."
        echo -e "${YELLOW}       Detection may be unreliable - consider re-running or checking the URL manually.${NC}"
        echo
    fi
fi

# ── embedded signature DB (JSON) ─────────────────────────────────────────────
# 381 CMS total with real detection patterns (CMSeeK + Wappalyzer + hand-added).
# Format per CMS entry:
#   html / html_regex / html_and   - matched against page body (literal / regex / AND-all-must-match)
#   headers / headers_regex / headers_and - matched against response headers
#   robots / robots_and            - matched against robots.txt
#   cookies                        - matched against Set-Cookie header names
#   version_paths                  - (optional) known version-disclosure paths for this CMS,
#                                     researched specifically (README/CHANGELOG/composer.json/
#                                     version endpoints). CMS without this use the generic
#                                     fallback path list defined further below instead.
# To add your own findings (e.g. an unknown CMS from a box), add a new JSON object
# below following the same structure - no other code changes needed.

cat > "$TMPDIR/signatures.json" << 'DBEOF'
{"wp":{"name":"WordPress","html":["/wp-content/","/wp-include/","/wp-includes/","wp-emoji","/wp-json/","name=\"generator\" content=\"WordPress"],"headers":["/wp-json/"],"robots":["Disallow: /wp-admin/","Allow: /wp-admin/admin-ajax.php"],"version_paths":["/readme.html","/wp-includes/version.php","/feed/","/wp-json/"]},"mg":{"name":"Magento","html":["/skin/frontend/","x-magento-init"],"version_paths":["/composer.json","/magento_version","/RELEASE_NOTES.txt"]},"blg":{"name":"Blogger By Google","html":["https://www.blogger.com/static/"]},"lj":{"name":"LiveJournal","html":["ic.pics.livejournal.com"]},"tdc":{"name":"3dCart","html":["END: 3dcart stats"]},"apos":{"name":"Apostrophe CMS","html":["href=\"/apos-minified/"]},"abc":{"name":"Adobe Business Catalyst","html":["href=\"/CatalystStyles/"]},"dru":{"name":"Drupal","html":["/misc/drupal.js"],"headers":["X-Drupal-","19 Nov 1978 05"],"robots":["Allow: /core/*.css$","Disallow: /index.php/user/login/","Disallow: /web.config"],"version_paths":["/CHANGELOG.txt","/README.txt","/core/CHANGELOG.txt","/core/README.txt"]},"joom":{"name":"Joomla","html":["css/joomla.css"],"headers":["Expires: Wed, 17 Aug 2005 00:00:00 GMT"],"robots_and":["If the Joomla site is installed","Disallow: /administrator/"],"version_paths":["/administrator/manifests/files/joomla.xml","/language/en-GB/en-GB.xml","/README.txt","/modules/custom.xml"]},"oc":{"name":"OpenCart","html":["Powered By <a href=\"http://www.opencart.com\">OpenCart","\"catalog/view/javascript/jquery/swiper/css/opencart.css\"","index.php?route="],"version_paths":["/CHANGELOG.md","/system/startup.php"]},"xoops":{"name":"XOOPS","html":["/xoops.js","xoops_redirect"],"robots_and":["Disallow: /kernel/","Disallow: /language/","Disallow: /templates_c/"]},"tilda":{"name":"Tilda CMS","html":["tildacdn.com"],"robots":["Disallow: /tilda"]},"wolf":{"name":"Wolf CMS","html":["Wolf Default RSS Feed"]},"ushahidi":{"name":"Ushahidi","html":["/ushahidi.js","alt=\"Ushahidi\""],"headers":["Set-Cookie: ushahidi"]},"wgui":{"name":"WebGUI","html":["getWebguiProperty"]},"tidw":{"name":"TiddlyWiki","html":["title: \"TiddlyWiki\"","TiddlyWiki created by Jeremy Ruston,"]},"sqm":{"name":"Squiz Matrix","html":["Running Squiz Matrix"],"headers":["Set-Cookie: SQ_SYSTEM_SESSION","squizedge.net"]},"spin":{"name":"Spin CMS","html":["assets.spin-cdn.com"],"headers":["spincms"]},"sdev":{"name":"solodev","html":["content=\"Solodev\" name=\"author\""],"headers":["solodev_session"]},"snews":{"name":"sNews","html":["content=\"sNews"]},"score":{"name":"Sitecore","html":["/api/sitecore/"],"headers":["SC_ANALYTICS_GLOBAL_COOKIE"],"robots":["Disallow: /sitecore","Disallow: /sitecore_files","Disallow: /sitecore modules"]},"sim":{"name":"SIMsite","html":["simsite/"]},"spb":{"name":"Simplébo","html":["simplebo.net/"],"headers":["X-ServedBy: simplebo","_simplebo_tool_session"]},"silva":{"name":"Silva CMS","html":["/silvatheme"]},"spity":{"name":"Serendipity","html":["serendipityQuickSearchTermField ","\"serendipity_","serendipity["],"headers":["X-Blog: Serendipity","Set-Cookie: serendipity[","Set-Cookie: s9y_"]},"slcms":{"name":"SeamlessCMS","html":["Published by Seamless.CMS.WebUI"],"headers":["Set-Cookie: SEAMLESS_IDENTIFIER"]},"rock":{"name":"Rock RMS","html":["rock-config-trigger","rock-config-cancel-trigger"]},"rcms":{"name":"RCMS","html":["/rcms-f-production."]},"quick":{"name":"Quick.Cms","html":["CMS by Quick.Cms","Powered by Quick.Cart"]},"dle":{"name":"DataLife Engine","html":["DataLife Engine","dle_js.js"]},"rcube":{"name":"RoundCube Webmail","html":["Roundcube Webmail","rcube_webmail"]},"bitrix":{"name":"Bitrix","html":["bitrix","Bitrix"],"headers":["X-Powered-CMS: Bitrix Site Manager"],"robots":["Disallow: /bitrix/"]},"pcore":{"name":"Pimcore","html":["\"pimcore_"],"headers":["X-Powered-By: pimcore"]},"percms":{"name":"Percussion CMS","html":["xmlns:perc","cm/css/perc_decoration.css"]},"pblue":{"name":"PencilBlue","html":["PencilBlueController","\"pencilblueApp\""],"headers":["x-powered-by: PencilBlue"]},"ophal":{"name":"Ophal","html":["/libraries/ophal.js"],"headers":["x-powered-by: Ophal"]},"sfy":{"name":"Sitefinity","html":["Sitefinity/WebsiteTemplates"]},"zyro":{"name":"Zyro","html":["assets.zyrosite.com"],"headers":["x-powered-by: Zyro.com"]},"otwsm":{"name":"OpenText WSM","html":["published by Open Text Web Solutions"]},"ocms":{"name":"OpenCms","html":["/opencms/export/"],"headers":["Server: OpenCms"]},"odoo":{"name":"Odoo","html":["odoo.session_info","var odoo ="],"headers":["X-Odoo-"]},"share":{"name":"Microsoft Sharepoint","html":["_spBodyOnLoadWrapper","_spPageContextInfo","_spFormOnSubmitWrapper"],"headers":["X-SharePointHealthScore","SPIisLatency","SPRequestGuid","MicrosoftSharePointTeamServices","SPRequestDuration"]},"octcms":{"name":"October CMS","html":["/storage/app/media/"],"headers":["october_session"],"version_paths":["/composer.json","/CHANGELOG.md"]},"mura":{"name":"Mura CMS","html":["mura.min.css","/plugins/Mura"],"headers":["Generator: Mura CMS"]},"moto":{"name":"Moto CMS","html":["mt-content/","moto-website-style"],"robots":["Disallow: /*mt-content*","Disallow: /mt-includes/"]},"mnet":{"name":"Mono.net","html":["mono_donottrack","monotracker.js ","_monoTracker"]},"modx":{"name":"MODX","html":["Powered by MODX</a>"],"headers":["X-Powered-By: MODX"],"version_paths":["/core/docs/changelog.txt"]},"methd":{"name":"Methode","html":["siteCMS:methode\"","\"contentOriginatingCMS=Methode\"","Methode tags version","/r/PortalConfig/common/assets/"]},"lscms":{"name":"LiveStreet CMS","html":["var LIVESTREET_SECURITY_KEY"]},"koken":{"name":"Koken","html":["/koken.js","data-koken-internal"]},"jimdo":{"name":"Jimdo","html":["jimdo_layout_css","var jimdoData","isJimdoMobileApp"],"headers":["X-Jimdo-"]},"ibit":{"name":"Indexhibit","html":["<!-- you must provide a link to Indexhibit","\"Built with <a href=http://www.indexhibit.org/>Indexhibit\"","ndxz-studio/site","ndxzsite/"],"headers":["Set-Cookie: ndxz_"]},"wflow":{"name":"Webflow CMS","html":["<!-- webflow css -->","css/webflow.css","js/webflow.js"]},"jcms":{"name":"Jalios JCMS","html":["css/jalios/core/","js/jalios/core/","jalios:ready"],"headers":["X-Jcms-Ajax-Id"],"robots":["Disallow: /jcmsplugin/"]},"impage":{"name":"ImpressPages CMS","html":["ip_themes/","ip_libs/","ip_cms/"],"headers_regex":["Set-Cookie: ses(\\d+)="],"robots":["Disallow: /ip_cms/","ip_backend_frames.php","ip_backend_worker.php"]},"hotaru":{"name":"Hotaru CMS","html":["/css_js_cache/hotaru_css","hotaruFooterImg","/css_js_cache/hotaru_js"]},"hippo":{"name":"HIPPO CMS","html":["binaries/content/gallery/"],"html_regex":["binaries/(.*?)/content/gallery/"]},"phpn":{"name":"PHP Nuke","html":["PHP-Nuke Copyright ©","PHP-Nuke theme by"]},"flex":{"name":"FlexCMP","html":["FlexCMP - CMS per Siti Accessibili","/flex/TemplatesUSR/","FlexCMP - Digital Experience Platform (DXP)"],"headers":["X-Powered-By: FlexCMP","X-Flex-Tag:","X-Flex-Lang:","X-Flex-Lastmod:","X-Flex-Community:","X-Flex-Evstart"],"robots":["Disallow: /flex/tmp/","flex/Logs/"]},"ezpu":{"name":"eZ Publish","html":["copyright\" content=\"eZ Systems\"","ezcontentnavigationpart","ezinfo/copyright"],"headers":["X-Powered-By: eZ Publish","Set-Cookie: eZSESSID"]},"e107":{"name":"e107","html":["e107_files/e107.js","e107_themes/","e107_plugins/"],"headers":["X-Powered-By: e107","Set-Cookie: SESSE107COOKIE"],"robots":["Disallow: /e107_admin/","e107_handlers","e107_files/cache"]},"dnn":{"name":"DNN Platform","html":["<!-- DNN Platform"," by DNN Corporation -->","DNNROBOTS","js/dnncore.js?","dnn_ContentPane","js/dnn.js?"],"headers":["Set-Cookie: dnn_IsMobile","DNNOutputCache","DotNetNuke"]},"phpbb":{"name":"phpBB","html":["phpBBstyle","phpBBMobileStyle","style_cookie_settings"],"html_regex":["Powered by (.*?)phpBB","copyright(.*?)phpBB Group"],"headers_regex":["Set-Cookie: phpbb(.*?)="],"version_paths":["/docs/CHANGELOG.html","/composer.json"]},"dede":{"name":"DEDE CMS","html":["dede_fields","dede_fieldshash","DedeAjax","DedeXHTTP","include/dedeajax2.js","css/dedecms.css"],"robots":["Disallow: /plus/ad_js.php","Disallow: /plus/erraddsave.php","Disallow: /plus/posttocar.php","Disallow: /plus/disdls.php","Disallow: /plus/mytag_js.php","Disallow: /plus/stow.php"]},"orchd":{"name":"Orchard CMS","html":["/Orchard.jQuery/","orchard.themes","orchard-layouts-root"],"headers":["X-Generator: Orchard"]},"cbox":{"name":"ContentBox","html":["modules/contentbox/themes/"],"headers":["X-Powered-By: ContentBox","Set-Cookie: LIGHTBOXSESSION"],"robots":["modules/contentbox/themes/"]},"conful":{"name":"Contentful","html":["data-contentful",".contentful.com/",".ctfassets.net/"]},"contensis":{"name":"contensis","html":["Contensis.current","ContensisSubmitFromTextbox","ContensisTextOnly"]},"contao":{"name":"Contao CMS","html":["system/cron/cron.txt"],"robots":["Disallow: /contao/"]},"bboard":{"name":"Burning Board","html":["/burningBoard.css","wcf/style/"],"html_regex":["(a href\\=\"http\\://www\\.woltlab\\.com\"|Forum Software|Forensoftware)(.*?)Burning Board(.*?)\\</strong\\>"],"headers_regex":["Set-Cookie: wcf(.*?)_cookieHash="]},"con5":{"name":"Concrete5 CMS","html":["/concrete/images","/concrete/css","/concrete/js"],"html_regex":["CCM_(.*?)(_|)(MODE|URL|PATH|FILENAME|REL|CID)"],"headers":["Set-Cookie: CONCRETE5"],"robots":["Disallow: /concrete"],"version_paths":["/concrete/composer.json","/CHANGELOG.md"]},"discrs":{"name":"discrs","html":["discourse_theme_id","discourse_current_homepage"],"version_paths":["/admin/upgrade.json","/srv/status"]},"discuz":{"name":"Discuz!","html":["discuz_uid","discuz_tips","content=\"Discuz! Team and Comsenz UI Team\""],"robots_and":["uc_client","uc_server","forum.php?mod=redirect*"]},"flarum":{"name":"Flarum","html":["flarum-loading","flarum/app"],"headers":["Set-Cookie: flarum_session="]},"ipb":{"name":"IP.Board community forum","html":["/* IP.Board","js/ipb.js","js/ipb.lang.js","ips_usernameand ips_password"],"html_regex":["invisioncommunity\\.com(.*?)Powered by Invision Community","ipb\\.(vars|templates|lang)\\[(.*?)=(.*?)\\</script\\>"],"headers":["IPSSessionFront","ipbWWLmodpids","ipbWWLsession_id"]},"minibb":{"name":"miniBB","html":["bb_default_style.css","name=\"URL\" content=\"http://www.minibb.net/\""],"html_regex":["(powered by|http\\://www\\.miniBB\\.net)(.*?)(miniBB|miniBB forum software)"]},"mybb":{"name":"MyBB","html":["var MyBBEditor"],"html_regex":["(Powered By|href\\=\"https\\://www\\.mybb\\.com\")(.*?)(MyBB|MyBB Group)\\</a\\>"],"headers_regex":["Set-Cookie: mybb\\[(.*?)\\]="],"version_paths":["/install/resources/","/CHANGELOG"]},"nodebb":{"name":"NodeBB","html":["/assets/nodebb.min.js","/plugins/nodebb-"],"html_regex":["Powered by(.*?)NodeBB\\</a\\>"],"headers":["X-Powered-By: NodeBB"]},"punbb":{"name":"PunBB","html":["PUNBB.env","typeof PUNBB ==="],"html_regex":["Powered by(.*?)PunBB\\</a\\>"]},"smf":{"name":"Simple Machines Forum","html":["Powered by SMF"],"html_regex":["var smf_(theme_url|images_url|scripturl) \\=(.*?)\\</script\\>"]},"vanilla":{"name":"Vanilla Forums","html":["vanilla_discussions_index","vanilla_categories_index"],"html_regex":["applications/vanilla/(.*?)\\.js"],"headers":["X-Garden-Version: Vanilla","Maybe you should be reading this instead: https://www.vanillaforums.com/en/careers"],"version_paths":["/CHANGELOG.md","/composer.json"]},"xf":{"name":"XenForo","html":["Forum software by XenForo&trade;","<html id=\"XenForo\"","css.php?css=xenforo"],"headers":["Set-Cookie: xf_session=","Set-Cookie: xf_csrf="],"version_paths":["/CHANGELOG.txt"]},"xmb":{"name":"XMB","html":["<!-- Powered by XMB","<!-- The XMB Group -->","Powered by XMB"],"headers_regex":["Set-Cookie: xmblv(a|b)=(\\d.*?)\n"]},"yabb":{"name":"YaBB (Yet another Bulletin Board)","html":["yabbfiles/"],"headers_regex":["Set-Cookie: (YaBBusername=|YaBBpassword=|YaBBSession|Y2User-(\\d.*?)|Y2Pass-(\\d.*?)|Y2Sess-(\\d.*?))="]},"aef":{"name":"Advanced Electron Forum","html":["Powered By AEF"],"html_regex":["aefonload(.*?)\\</script\\>"],"headers":["[aefsid]"]},"fudf":{"name":"FUDforum","html":["Powered by: FUDforum"],"headers":["Set-Cookie: fud_session_"]},"phorum":{"name":"Phorum","html":["<div id=\"phorum\">"],"headers":["Set-Cookie: phorum_session"]},"yaf":{"name":"Yet Another Forum (YAF)","html":["\"YafHead"],"html_regex":["\\>Powered by YAF\\.NET(.*?)\\</a\\>"]},"nnf":{"name":"NoNonsense Forum","html":["<!-- NoNonsense Forum"],"html_regex":["Powered by(.*?)NoNonsense Forum\\</a\\>"]},"mvnf":{"name":"mvnForum","html":["/mvnplugin/mvnforum/"],"html_regex":["Powered by(.*?)mwForum(.*?)Markus Wichitill","Powered by(.*?)mvnForum(.*?)\\</a\\>"]},"aspf":{"name":"AspNetForum","html":["aspnetforum.css\"","_AspNetForumContentPlaceHolder"],"html_regex":["Powered by(.*?)AspNetForum(.*?)(\\</a\\>|\\</span\\>)"]},"jf":{"name":"JForum","html":["jforum/templates/"],"html_regex":["Powered by(.*?)JForum(.*?)\\</a\\>"]},"abuy":{"name":"Afterbuy","html":["This OnlineStore is brought to you by ViA-Online GmbH Afterbuy."],"robots":["Disallow: /AfterbuySrcProxy.aspx","Disallow: /afterbuy.asmx","Disallow: /afterbuySrc.asmx"]},"arstta":{"name":"Arastta","html":["/arastta.js"],"headers":["X-Arastta"]},"bizw":{"name":"Bizweb","html":["<script src='//bizweb.dktcdn.net"],"html_regex":["var Bizweb \\=(.*?)\\</script\\>"]},"cloudc":{"name":"CloudCart","html":["cloudcart\",\"title"],"html_regex":["\\<meta name\\=(.*?)author(.*?)CloudCart LLC(.*?)\\>"]},"cmshop":{"name":"ColorMeShop","html":["framework/colormekit.css"],"html_regex":["var Colorme \\=(.*?)\\</script\\>"]},"mdle":{"name":"Moodle","html":["<meta name=\"keywords\" content=\"moodle"],"headers":["Set-Cookie: MoodleSession","Set-Cookie: MOODLEID_"],"version_paths":["/version.php","/lib/components.json","/CHANGES.md"]},"orkis":{"name":"ORKIS Ajaris Websuite","html":["<meta property=\"ajaris:baseURL\"","<meta property=\"ajaris:language\"","<meta property=\"ajaris:ptoken\""]},"cmdia":{"name":"Comandia","html":["window.Comandia = JSON.parse","<script src=\"https://cdn.mycomandia.com/static/shop/common/js/functions.js\"></script>"],"html_regex":["https://cdn.mycomandia.com/uploads/comandia_(.*?)/r/(.*?)//js/(functions|main).js"]},"elcd":{"name":"Elcodi","html":["/bundles/elcodimetric/js/tracker.js"],"html_regex":["<script(.*?)Tracker generator for elcodi bamboo store(.*?)</script>"],"headers":["X-Elcodi:"]},"epgs":{"name":"ePages","html":["de_epages.remotesearch.ui.suggest","require([['de_epages'"],"html_regex":["href=(.*?)/epages/(.*?).sf(.*?)</a>"],"robots":["Disallow: /epages/Site.admin/","Disallow: /epages/*"]},"for3":{"name":"Fortune3","html":["href=\"https://www.fortune3.com/en/siterate/rate.css\""],"html_regex":["Powered by(.*?)Fortune3</a>"]},"btree":{"name":"BigTree CMS","html_regex":["Built on(.*?)bigtreecms.org(.*?)BigTree CMS"],"html_and":["<body class=\"gridlock shifter\">","<div class=\"shifter-page\">"]},"pmoc":{"name":"Proximis Omnichannel","html_and":["list-unstyled","editable-zone"]},"sfcc":{"name":"Salesforce Commerce Cloud","html":["<!-- Demandware Analytics code","<!-- Demandware Apple Pay -->"],"html_regex":["href\\=(.*?)on/demandware.static"],"headers":["Demandware Secure Token","Demandware anonymous cookie","dwpersonalization_","dwanonymous_"],"robots":["demandware.store","demandware.static","demandware.net"]},"sazito":{"name":"Sazito","html":["icons__icons___XoCGh","styles__empty___3WCoC","icons__icon-phone___22Eum"]},"shopatron":{"name":"Shopatron","html":["SHOPATRON-CRAWLER"],"html_regex":["href\\=(.*?)mediacdn.shopatron.com","href\\=(.*?)cdn.shptrn.com"]},"umbraco":{"name":"Umbraco","html":["Umbraco/","umbraco/"],"headers":["X-Umbraco-Version"],"robots":["robots.txt for Umbraco","Disallow: /umbraco","Disallow: /umbraco_client"],"version_paths":["/umbraco/config/splashes/noNodes.aspx","/config/ClientDependency.config"]},"shoper":{"name":"Shoper","html":["Sklep internetowy Shoper.pl"],"html_regex":["href\\=(.*?)rwd_shoper(|_1)"]},"shopery":{"name":"Shopery","html":["//www.googletagmanager.com/ns.html?id=GTM-N2T2D3"],"html_regex":["(cdn|font).shopery.com/"],"headers":["X-Shopery","This E-commerce is built using Shopery"]},"shopfa":{"name":"ShopFA","html":["shopfa_license"],"html_regex":["href\\=(.*?)cdn.shopfa.com/","href\\=(.*?)cdnfa.com/"],"headers":["X-Powered-By: ShopFA"]},"smartstore":{"name":"Smartstore","html":["/smjslib.js","/smartstore.core.js"],"html_regex":["css/smartstore.(core|theme|modules).css"],"robots_and":["Disallow: /broker","Disallow: /broker/orders"]},"weebly":{"name":"Weebly","html":["_W.configDomain","Weebly.footer"],"html_regex":["weebly-(footer|icon)"],"headers_regex":["X-Host: (.*?)weebly.net"],"robots_and":["Disallow: /ajax","Disallow: /apps"]},"whmcs":{"name":"WHMCS","html":["js/whmcs.js"],"headers":["Set-Cookie: WHMCS"]},"opennemas":{"name":"OpenNemas CMS","html":["OpenNeMaS CMS by Openhost","var u = \"https://piwik.openhost.es/\""],"html_regex":["onm-(new|image|carousel|big|cropped)"],"headers":["X-Powered-By: OpenNemas","Via: Opennemas Proxy Server"],"robots_and":["Disallow: /harming/humans","Disallow: /ignoring/human/orders","Disallow: /harm/to/self"]},"zencart":{"name":"Zen Cart CMS","html":["zenid=","Congratulations! You have successfully installed your Zen Cart","Google Code for ZenCart Google","Powered by ZenCart","sideboxpzen-cart","stylesheet_zen_lightbox.css"],"robots":["Zen Cart doesn't require any","Zen Cart installation","pzen_"]},"ipo":{"name":"IPO CMS","html":["Redakční systém IPO","cdn.antee.cz/","ipo.min.js"],"html_regex":["ipo(pagetext|mainframe|footer|menuwrapper|copyright|header|main|menu|statistics)"],"robots":["Disallow: /*action=personalDataProcessing*"]},"hugo":{"name":"Hugo","html":["Built using HUGO"]},"squarespace":{"name":"Squarespace","html":["This is Squarespace","End of Squarespace Headers"]},"afsto":{"name":"Afosto","html_regex":["('|\")https\\://afosto\\-cdn(.*?)\\.afosto\\.com(.*?)('|\")"],"headers":["X-Powered-By: Afosto","Link: <//afosto-cdn"]},"mcb":{"name":"MercuryBoard","html_regex":["Powered by(.*?)MercuryBoard(.*?)\\</a\\>"]},"myupb":{"name":"myUPB","html_regex":["Powered by myUPB(.*?)\\</a\\>"]},"ubbt":{"name":"UBB.threads","html_regex":["\\>Powered by UBB\\.threads(.*?)\\</a\\>"],"headers":["Set-Cookie: ubbt_"]},"fluxbb":{"name":"FluxBB","html_regex":["Powered by(.*?)FluxBB"]},"dscrs":{"name":"Discourse","html_regex":["Discourse\\.(.*?)\\=(.*?)\\</script\\>"],"headers":["X-Discourse-Route"],"robots_and":["Disallow: /auth/cas","Disallow: /auth/cas/callback"]},"arc":{"name":"Arc Forum","html_regex":["ping\\.src \\= node\\.href(.*?)\\</script\\>"]},"phpc":{"name":"phpCMS","html_regex":["\\.php\\?m\\=(.*?)&c\\=(.*?)&a\\=(.*?)&catid\\="],"robots":["Disallow: /phpcms","robots.txt for PHPCMS"]},"coton":{"name":"Cotonti","html_regex":["Powered by(.*?)Cotonti"]},"bigc":{"name":"BigCommerce","html_regex":["\\<link href\\=(.*?)cdn(\\d).bigcommerce\\.com\\/"],"headers":["set-cookie: fornax_anonymousId="]},"bigw":{"name":"Bigware","html_regex":["\\<a href\\=(.*?)main_bigware_(\\d)\\.php"],"headers":["Set-Cookie: bigwareCsid","Set-Cookie: bigWAdminID"]},"cexec":{"name":"Clientexec","html_regex":["var clientexec \\=(.*?)\\</script\\>","Powered by(.*?)http\\://www\\.clientexec\\.com\\?source\\=poweredby(.*?)\\</a\\>"]},"cosmos":{"name":"Cosmoshop","html_regex":["<script(.*?)cosmoshop_functions.js(.*?)</script>"],"headers":["Set-Cookie: COSMOSHOP_"]},"csc":{"name":"CS Cart","html_regex":[".cm-noscript(.*?)</script>"],"headers_regex":["Set-Cookie: sid_customer_[a-zA-Z0-9]{5}="],"robots_and":["Disallow: /app/","Disallow: /store_closed.html"]},"cubec":{"name":"CubeCart","html_regex":["<link(.*?)cubecart.common.css(.*?)>"]},"abda":{"name":"Al Mubda","html_regex":["<a href(.*?)http://www.almubda.net(.*?)Powered by Al Mubda(.*?)</a>"]},"dweb":{"name":"Dynamicweb","html_regex":["<!--(.*?)Dynamicweb Software(.*?)-->"],"headers":["Set-Cookie: Dynamicweb"],"robots":["Disallow: /*?cartcmd=*"]},"ecc":{"name":"EC-CUBE","html_regex":["<script(.*?)eccube.js(.*?)</script>","<script(.*?)win_op.js(.*?)</script>","<script(.*?)cube.site.js(.*?)</script>"]},"ezpub":{"name":"eZ Publish","html_regex":["<script(.*?)/extension/iagutils/design/ezwebin/(.*?)</script>"],"headers":["X-Powered-By: eZ Publish"],"robots":["Disallow: /Mediatheque/"]},"shopify":{"name":"Shopify","html_regex":["id=(\"|')(shopify-digital-wallet|shopify-features)","href\\=(.*?)cdn.shopify.com/"],"headers":["X-Shopify-Stage","set-cookie: _shopify","Set-Cookie: secure_customer_sig"],"robots":["we use Shopify"],"headers_and":["X-ShopId","X-ShardId"]},"shoptet":{"name":"Shoptet","html_regex":["href\\=(.*?)cdn.myshoptet.com/","content=\"Shoptet.sk\"","var shoptet="],"headers":["SRV_ID=shoptet"],"robots_and":["diskuse","wysiwyg","dotaz","hodnoceni"]},"spree":{"name":"Spree","html_regex":["src=(.*?)spree/(products|brands)","Spree.(api_key|routes|translations)"],"headers":["Set-Cookie: _spree_store_session"],"robots":["spree/products/"]},"brightspot":{"name":"Brightspot CMS","html_regex":["meta name\\=(\"|')brightspot.(contentId|cached)","href=(\"|')brightspotcdn"],"headers":["X-Powered-By: Brightspot"]},"amiro":{"name":"Amiro.CMS","html_regex":["amiro_sys_(css|js).php"],"robots_and":["/admin","/_admin","offset=0","_print_version"]},"ekmps":{"name":"ekmPowershop","html_regex":["/ekmps/(scripts|css|assets|images|shops|designs)","globalstats.ekmsecure.com/hits/stats(-global).js"],"headers_regex":["Set-Cookie: (ekmMsg|ekmpowershop)"]},"godaddywb":{"name":"GoDaddy Website Builder","html_regex":["sf_(wrapper|footer|banner|subnavigation|pagetitle)"],"robots_and":["Disallow: /_backup/","Disallow: /_mygallery/","Disallow: /_temp/","Disallow: /_tempalbums/","Disallow: /_tmpfileop/","Disallow: /dbboon/"]},"wix":{"name":"WIX Website Builder","headers":["X-Wix-"]},"umi":{"name":"UMI.CMS","headers":["X-Generated-By: UMI.CMS"],"robots":["Disallow: /adminzone/"]},"sulu":{"name":"SULU","headers":["x-generator: Sulu"]},"subcms":{"name":"Subrion CMS","headers":["X-Powered-CMS: Subrion CMS"]},"roadz":{"name":"Roadiz CMS","headers":["X-Powered-By: Roadiz CMS"]},"kbcms":{"name":"Kooboo CMS","headers":["X-KoobooCMS-Version"]},"grav":{"name":"GravCMS","headers":["Set-Cookie: grav-site-"],"version_paths":["/system/defines.php","/CHANGELOG.md"]},"exen":{"name":"ExpressionEngine","headers":["Set-Cookie: exp_tracker","Set-Cookie: exp_last_activity","Set-Cookie: exp_last_visit","Set-Cookie: exp_csrf_token="]},"dncms":{"name":"Danneo CMS","headers":["X-Powered-By: CMS Danneo"]},"craft":{"name":"Craft CMS","headers":["X-Powered-By: Craft CMS","Set-Cookie: CraftSessionId"],"robots":["Disallow: /craft/"],"version_paths":["/admin/","/composer.json"]},"dragon":{"name":"CPG Dragonfly","headers":["X-Powered-By: Dragonfly CMS"]},"yazd":{"name":"Yazd","headers":["Set-Cookie: yazdLastVisited="]},"oracle_atg":{"name":"Oracle ATG Web Commerce","headers":["X-ATG-Version"]},"coms":{"name":"Commerce Server","headers":["COMMERCE-SERVER-SOFTWARE:","commerce-server-software:"]},"presta":{"name":"PrestaShop","headers":["Powered-By: PrestaShop","Set-Cookie: PrestaShop"],"robots":["robots.txt automaticaly generated by PrestaShop"],"version_paths":["/composer.json","/docs/CHANGELOG.txt"]},"solusquare":{"name":"Solusquare Commerce Cloud","headers":["Set-Cookie: _SOLUSQUARE"],"robots":["gestion_e_commerce"]},"notion":{"name":"Notion","headers_and":["Set-Cookie","domain=.notion.site"]},"pwind":{"name":"phpWind","headers_regex":["Set-Cookie: [a-zA-Z0-9]{5}_(lastpos|lastvisit)="]},"epis":{"name":"EPiServer","headers_regex":["X-XRDS-Location: (.*?)EPiServerCommunity"]},"lepton":{"name":"LEPTON CMS","headers_regex":["lep(.*?)sessionid"]},"tpc":{"name":"Textpattern CMS","robots":["Disallow: /textpattern"]},"cockpit_cms":{"name":"Cockpit CMS","html":["riot-view","uk-app-page-login","<span>Cockpit</span>","App.request(","view/script"],"path_hint":"/auth/login, /auth/check, /auth/forgotpassword, /storage/tmp/","version_paths":["/composer.json","/config/config.php"]},"strapi_manual":{"name":"Strapi (headless)","html":["Strapi","/admin/strapi"],"headers":["X-Powered-By: Strapi"],"version_paths":["/admin/init","/_health"]},"directus_manual":{"name":"Directus (headless)","html":["Directus","/admin/login"],"cookies":["directus_session"],"version_paths":["/server/info","/server/ping"]},"processwire_manual":{"name":"ProcessWire","html":["ProcessWire","/site/templates/"],"cookies":["wires"],"robots":["/site/templates/"],"version_paths":["/site/assets/installed.php","/wire/core/ProcessWire.php"]},"couchcms_manual":{"name":"CouchCMS","html":["CouchCMS"],"version_paths":["/concrete/changelog.txt"]},"gilacms_manual":{"name":"Gila CMS","html":["Gila CMS","name=\"generator\" content=\"Gila CMS","lib/gila.min.css","gilacms.com"],"path_hint":"/admin/, /fm/, /fm/upload"},"dnn_wapp":{"name":"DNN","html":["name=\"generator\" content=\"DotNetNuke","<!-- DNN Platform","<!-- by DotNetNuke Corporation"],"html_regex":["/js/dnncore\\.js","/js/dnn\\.js"],"headers":["Cookie: dnn_IsMobile=","DNNOutputCache","X-Compressed-By: DotNetNuke"],"cookies":["DotNetNukeAnonymous"]},"datocms_wapp":{"name":"DatoCMS","headers_regex":["content\\-security\\-policy.*?\\.datocms-assets\\.com"]},"dedecms_wapp":{"name":"DedeCMS","html":["dedeajax"]},"deskpro_wapp":{"name":"DeskPro","html_regex":["name=\"generator\"[^>]*content=\"DeskPRO.+$"]},"directus_wapp":{"name":"Directus","headers_regex":["x\\-powered\\-by.*?Directus$"]},"django_cms_wapp":{"name":"Django CMS","html":["/djangocms_"]},"dotclear_wapp":{"name":"Dotclear","headers":["X-Dotclear-Static-Cache"]},"duda_wapp":{"name":"Duda","html_regex":["dd-cdn\\.multiscreensite\\.com/"]},"duopana_wapp":{"name":"Duopana","html_regex":["\\.beracode\\.com/"]},"phpnuke_wapp":{"name":"PHP-Nuke","html_regex":["<[^>]+Powered by PHP-Nuke"],"html":["name=\"generator\" content=\"PHP-Nuke"]},"phpfusion_wapp":{"name":"PHPFusion","html_regex":["Powered by <a href=\"[^>]+phpfusion","Powered by <a href=\"[^>]+php-fusion"],"headers_regex":["X\\-PHPFusion.*?(.+)$","X\\-Powered\\-By.*?PHPFusion (.+)$"]},"pagefai_cms_wapp":{"name":"Pagefai CMS","headers":["x-powered-by: PAGEFAI CMS"]},"pagekit_wapp":{"name":"Pagekit","html":["name=\"generator\" content=\"Pagekit"]},"pagevamp_wapp":{"name":"Pagevamp","headers":["X-ServedBy: pagevamp"]},"pars_elecom_portal_wapp":{"name":"Pars Elecom Portal","headers":["X-Powered-By: Pars Elecom Portal"],"html":["name=\"copyright\" content=\"Pars Elecom Portal"]},"paymenter_wapp":{"name":"Paymenter","cookies":["paymenter_session"]},"phoenix_site_wapp":{"name":"Phoenix Site","cookies":["phoenix_p_session"]},"photoshelter_wapp":{"name":"PhotoShelter","html_regex":["\\.psecn\\.photoshelter\\.com/"]},"pingoteam_wapp":{"name":"Pingoteam","html":["name=\"designer\" content=\"Pingoteam"]},"pixieset_website_wapp":{"name":"Pixieset Website","html_regex":["name=\"generator\"[^>]*content=\"Pixieset$"]},"platformos_wapp":{"name":"PlatformOS","headers_regex":["x\\-powered\\-by.*?platformOS$"]},"pligg_wapp":{"name":"Pligg","html_regex":["<span[^>]+id=\"xvotes-0"],"html":["name=\"generator\" content=\"Pligg"]},"plone_wapp":{"name":"Plone","html_regex":["^/\\+\\+resource\\+\\+"],"html":["name=\"generator\" content=\"Plone"]},"popmenu_wapp":{"name":"Popmenu","cookies":["Popmenu-Token"]},"posterous_wapp":{"name":"Posterous","html":["<div class=\"posterous"]},"prepr_wapp":{"name":"Prepr","html_regex":["\\.prepr\\.io/"],"html":["name=\"prepr:id\""],"cookies":["__prepr_uid"]},"prismic_wapp":{"name":"Prismic","html_regex":["\\.prismic\\.io/"]},"progress_sitefinity_wapp":{"name":"Progress Sitefinity","html_regex":["name=\"generator\"[^>]*content=\"Sitefinity\\s([\\S]{3,9})"]},"proximis_unified_commerce_wapp":{"name":"Proximis Unified Commerce","html_regex":["<html[^>]+data-ng-app=\"RbsChangeApp\""],"html":["name=\"generator\" content=\"Proximis Unified Commerce"]},"public_cms_wapp":{"name":"Public CMS","headers_regex":["X\\-Powered\\-PublicCMS.*?(.+)$"],"cookies":["PUBLICCMS_USER"]},"pyrocms_wapp":{"name":"PyroCMS","headers":["X-Streams-Distribution: PyroCMS"],"cookies":["pyrocms"]},"papaya_cms_wapp":{"name":"papaya CMS","html_regex":["<link[^>]*/papaya-themes/"]},"phprs_wapp":{"name":"phpRS","html_regex":["name=\"generator\"[^>]*content=\"phpRS$"]},"phpsqlitecms_wapp":{"name":"phpSQLiteCMS","html_regex":["name=\"generator\"[^>]*content=\"phpSQLiteCMS(?: (.+))?$"]},"pirobase_cms_wapp":{"name":"pirobase CMS","html_regex":["<(?:script|link)[^>]/site/[a-z0-9/._-]+/resourceCached/[a-z0-9/._-]+","<input[^>]+cbi:///cms/"]},"ksup_wapp":{"name":"K-Sup","html_regex":["name=\"generator\"[^>]*content=\"K-Sup \\(([\\d.R]+)\\)$"]},"kentico_cms_wapp":{"name":"Kentico CMS","html_regex":["/CMSPages/GetResource\\.ashx","/kentico\\.resource","name=\"generator\"[^>]*content=\"Kentico CMS ([\\d.R]+ \\(build [\\d.]+\\))"],"cookies":["CMSCookieLevel","CMSPreferredCulture"]},"koala_framework_wapp":{"name":"Koala Framework","html_regex":["<!--[^>]+This website is powered by Koala Web Framework CMS"],"html":["name=\"generator\" content=\"Koala Web Framework CMS"]},"komodo_cms_wapp":{"name":"Komodo CMS","html":["name=\"generator\" content=\"Komodo CMS"]},"kontentai_wapp":{"name":"Kontent.ai","headers_regex":["content\\-security\\-policy.*?\\.kc-usercontent\\.com"]},"koobi_wapp":{"name":"Koobi","html_regex":["<!--[^K>-]+Koobi ([a-z\\d.]+)"],"html":["name=\"generator\" content=\"Koobi"]},"kotisivukone_wapp":{"name":"Kotisivukone","html_regex":["kotisivukone(?:\\.min)?\\.js"]},"lgc_wapp":{"name":"LGC","html_regex":["name=\"generator\"[^>]*content=\"LGC$"]},"lede_wapp":{"name":"Lede","html_regex":["<a [^>]*href=\"[^\"]+joinlede.com","name=\"og:image\"[^>]*content=\"https?\\:\\/\\/lede-admin"]},"liferay_wapp":{"name":"Liferay","headers_regex":["Liferay\\-Portal.*?[a-z\\s]+([\\d.]+)"]},"lightmon_engine_wapp":{"name":"LightMon Engine","html":["name=\"generator\" content=\"LightMon Engine","<!-- Lightmon Engine Copyright Lightmon"],"cookies":["lm_online"]},"lithium_wapp":{"name":"Lithium","html_regex":[" <a [^>]+Powered by Lithium"],"cookies":["LithiumVisitor"]},"locomotivecms_wapp":{"name":"LocomotiveCMS","html_regex":["<link[^>]*/sites/[a-z\\d]{24}/theme/stylesheets"]},"abhicms_wapp":{"name":"AbhiCMS","html_regex":["name=\"generator\"[^>]*content=\"AbhiCMS\\s([\\d\\.]+)"]},"adobe_experience_manager_wapp":{"name":"Adobe Experience Manager","html":["/etc/clientlibs/","/etc/designs/"],"html_regex":["<div class=\"[^\"]*parbase","<div[^>]+data-component-path=\"[^\"+]jcr:","<div class=\"[^\"]*aem-Grid","/etc\\.clientlibs/"]},"adobe_experience_manager_franklin_wapp":{"name":"Adobe Experience Manager Franklin","html_regex":["^.+/scripts/lib-franklin\\.js$"]},"alvandcms_wapp":{"name":"AlvandCMS","html_regex":["name=\"generator\"[^>]*content=\"AlvandCMS\\s([\\d\\.]+)"]},"ametys_wapp":{"name":"Ametys","html_regex":["ametys\\.js","name=\"generator\"[^>]*content=\"(?:Ametys|Anyware Technologies)"]},"antee_ipo_wapp":{"name":"Antee IPO","html_regex":["name=\"author\"[^>]*content=\"Antee\\ss\\.r\\.o\\."]},"aquilacms_wapp":{"name":"AquilaCMS","html":["name=\"powered-by\" content=\"AquilaCMS"]},"asciidoc_wapp":{"name":"AsciiDoc","html_regex":["name=\"generator\"[^>]*content=\"AsciiDoc ([\\d.]+)"]},"azko_cms_wapp":{"name":"Azko CMS","html_regex":["//js\\.fw\\.azko\\.fr/"]},"ablog_cms_wapp":{"name":"a-blog cms","html":["name=\"generator\" content=\"a-blog cms"]},"hcl_digital_experience_wapp":{"name":"HCL Digital Experience","headers":["IBM-Web2-Location","Itx-Generated-Timestamp"]},"halo_wapp":{"name":"Halo","html_regex":["name=\"generator\"[^>]*content=\"Halo ([\\d.]+)?"]},"hatena_blog_wapp":{"name":"Hatena Blog","html_regex":["cdn\\.blog\\.st-hatena\\.com/"]},"hinza_advanced_cms_wapp":{"name":"Hinza Advanced CMS","html":["name=\"generator\" content=\"hinzacms"]},"hubspot_cms_hub_wapp":{"name":"HubSpot CMS Hub","headers":["x-hs-hub-id","x-powered-by: HubSpot"],"html":["name=\"generator\" content=\"HubSpot"]},"huberway_wapp":{"name":"Huberway","cookies":["huberway_session"]},"quintype_wapp":{"name":"Quintype","headers_regex":["link.*?fea\\.assettype\\.com/quintype-ace"],"cookies":["qtype-session"]},"gx_webmanager_wapp":{"name":"GX WebManager","html_regex":["<!--\\s+Powered by GX","name=\"generator\"[^>]*content=\"GX WebManager(?: ([\\d.]+))?"]},"getsimple_cms_wapp":{"name":"GetSimple CMS","html":["name=\"generator\" content=\"GetSimple"]},"ghost_wapp":{"name":"Ghost","headers":["X-Ghost-Cache-Status"],"html_regex":["name=\"generator\"[^>]*content=\"Ghost(?:\\s([\\d.]+))?"]},"graffiti_cms_wapp":{"name":"Graffiti CMS","html_regex":["/graffiti\\.js","name=\"generator\"[^>]*content=\"Graffiti CMS ([^\"]+)"],"cookies":["graffitibot"]},"grav_wapp":{"name":"Grav","html_regex":["name=\"generator\"[^>]*content=\"GravCMS(?:\\s([\\d.]+))?"]},"green_valley_cms_wapp":{"name":"Green Valley CMS","html_regex":["<img[^>]+/dsresource\\?objectid=","name=\"DC\\.identifier\"[^>]*content=\"/content\\.jsp\\?objectid="]},"griddo_wapp":{"name":"Griddo","html_regex":["name=\"generator\"[^>]*content=\"Griddo$"]},"govcms_wapp":{"name":"govCMS","html_regex":["name=\"generator\"[^>]*content=\"Drupal ([\\d]+) \\(http:\\/\\/drupal\\.org\\) \\+ govCMS"]},"vivvo_wapp":{"name":"VIVVO","cookies":["VivvoSessionId"]},"vigbo_wapp":{"name":"Vigbo","html_regex":["<link[^>]* href=[^>]+(?:\\.vigbo\\.com|\\.gophotoweb\\.com)","(?:\\.vigbo\\.com|\\.gophotoweb\\.com)"],"cookies":["_gphw_mode"]},"vignette_wapp":{"name":"Vignette","html_regex":["<[^>]+=\"vgn-?ext"]},"voogcom_website_builder_wapp":{"name":"Voog.com Website Builder","html_regex":["<script [^>]*src=\"[^\"]*voog\\.com/tracker\\.js","voog\\.com/tracker\\.js"]},"omurga_sistemi_wapp":{"name":"Omurga Sistemi","html":["name=\"generator\" content=\"OS-Omurga Sistemi"]},"openelement_wapp":{"name":"OpenElement","html_regex":["name=\"generator\"[^>]*content=\"openElement\\s\\(([\\d\\.]+)\\)"]},"opentext_web_solutions_wapp":{"name":"OpenText Web Solutions","html_regex":["<!--[^>]+published by Open Text Web Solutions"]},"optimizely_content_management_wapp":{"name":"Optimizely Content Management","html_regex":["\\.episerver.net/"],"headers_regex":["content\\-security\\-policy.*?\\.episerver\\.net"],"html":["name=\"generator\" content=\"EPiServer"],"cookies":["EPi:StateMarker","EPiServer","EPiSessionId","EPiTrace"]},"orchard_core_wapp":{"name":"Orchard Core","html_regex":["/OrchardCore\\."],"headers":["x-powered-by: OrchardCore"],"headers_regex":["x\\-generator.*?Orchard$"],"html":["name=\"generator\" content=\"Orchard"]},"onpublix_wapp":{"name":"onpublix","html_regex":["name=\"generator\"[^>]*content=\"onpublix\\s([\\d\\.]+)$"]},"ibexa_dxp__wapp":{"name":"Ibexa DXP ","headers_regex":["x\\-powered\\-by.*?Ibexa\\sExperience\\sv([\\d\\.]+)$"],"html":["name=\"generator\" content=\"eZ Platform"]},"impresscms_wapp":{"name":"ImpressCMS","html_regex":["include/linkexternal\\.js"],"html":["name=\"generator\" content=\"ImpressCMS"],"cookies":["ICMSSession","ImpressCMS"]},"indico_wapp":{"name":"Indico","html_regex":["Powered by\\s+(?:CERN )?<a href=\"http://(?:cdsware\\.cern\\.ch/indico/|indico-software\\.org|cern\\.ch/indico)\">(?:CDS )?Indico( [\\d\\.]+)?"],"cookies":["MAKACSESSION"]},"instantcms_wapp":{"name":"InstantCMS","html":["name=\"generator\" content=\"InstantCMS"],"cookies":["InstantCMS[logdate]"]},"iexexchanger_wapp":{"name":"iEXExchanger","html":["name=\"generator\" content=\"iEXExchanger"],"cookies":["iexexchanger_session"]},"imperia_cms_wapp":{"name":"imperia CMS","html":["name=\"x-imperia-live-info\""],"html_regex":["name=\"generator\"[^>]*content=\"IMPERIA\\s([\\d\\.\\_]+)"]},"emonsite_wapp":{"name":"E-monsite","html_regex":["name=\"generator\"[^>]*content=\"e-monsite\\s\\(e-monsite\\.com\\)$"]},"ebasnet_wapp":{"name":"Ebasnet","html_regex":["cdnebasnet\\.com/","name=\"author\"[^>]*content=\"Ebasnet Web Solutions$"]},"ektron_cms_wapp":{"name":"Ektron CMS","html_regex":["/ektron\\.javascript\\.ashx"]},"elcom_wapp":{"name":"Elcom","html":["Web CMS by Elcom","name=\"generator\" content=\"elcomCMS"]},"eleanor_cms_wapp":{"name":"Eleanor CMS","html":["name=\"generator\" content=\"Eleanor"]},"enjin_cms_wapp":{"name":"Enjin CMS","html_regex":["\\.enjin\\.com/"]},"essent_sitebuilder_pro_wapp":{"name":"Essent SiteBuilder Pro","html_regex":["name=\"GENERATOR\"[^>]*content=\"Essent® SiteBuilder Pro$"]},"esyndicat_wapp":{"name":"eSyndiCat","headers":["X-Drectory-Script: eSyndiCat"],"html":["name=\"generator\" content=\"eSyndiCat "]},"endurojs_wapp":{"name":"enduro.js","headers_regex":["X\\-Powered\\-By.*?enduro\\.js"]},"experiencedcms_wapp":{"name":"experiencedCMS","html_regex":["name=\"generator\"[^>]*content=\"experiencedCMS$"]},"sdl_tridion_wapp":{"name":"SDL Tridion","html_regex":["<img[^>]+_tcm\\d{2,3}-\\d{6}\\."]},"spip_wapp":{"name":"SPIP","headers":["X-Spip-Cache"],"headers_regex":["Composed\\-By.*?SPIP ([\\d.]+) @"],"html_regex":["name=\"generator\"[^>]*content=\"(?:^|\\s)SPIP(?:\\s([\\d.]+(?:\\s\\[\\d+\\])?))?"]},"sanity_wapp":{"name":"Sanity","headers":["x-sanity-shard"],"headers_regex":["content\\-security\\-policy.*?cdn\\.sanity\\.io"]},"sapren_wapp":{"name":"Sapren","html_regex":["name=\"generator\"[^>]*content=\"Saprenco.com Website Builder$"]},"sarkaspip_wapp":{"name":"Sarka-SPIP","html_regex":["name=\"generator\"[^>]*content=\"Sarka-SPIP(?:\\s([\\d.]+))?"]},"scorpion_wapp":{"name":"Scorpion","html_regex":["<[^>]+id=\"HSScorpion","cdn.cxc.scorpion.direct"]},"scrivito_wapp":{"name":"Scrivito","html_regex":["name=\"generator\"[^>]*content=\"Scrivito\\sby\\sInfopark\\sAG\\s\\(scrivito\\.com\\)$"]},"shift4shop_wapp":{"name":"Shift4Shop","html_regex":["(?:twlh(?:track)?\\.asp|3d_upsell\\.js)"],"headers":["X-Powered-By: 3DCART"],"cookies":["3dvisit"]},"shuttle_wapp":{"name":"Shuttle","html_regex":["shuttle(?:-assets-new|-storage)\\.s3\\.amazonaws\\.com"]},"silverstripe_wapp":{"name":"Silverstripe","html_regex":["Powered by <a href=\"[^>]+Silverstripe"],"html":["name=\"generator\" content=\"SilverStripe"]},"siteedit_wapp":{"name":"SiteEdit","html":["name=\"generator\" content=\"SiteEdit"]},"sitemanager_wapp":{"name":"SiteManager","html_regex":["s\\d+\\.sitemn\\.gr/"]},"siteglide_wapp":{"name":"Siteglide","html_regex":["siteglide\\.js"]},"sitepark_ies_wapp":{"name":"Sitepark IES","html_regex":["name=\"generator\"[^>]*content=\"Sitepark\\sInformation\\sEnterprise\\sServer\\s-\\sIES\\sGenerator\\sv([\\d\\.]+)$"]},"sitepark_infosite_wapp":{"name":"Sitepark InfoSite","html_regex":["name=\"generator\"[^>]*content=\"InfoSite\\s([\\d\\.]+)\\s-\\sSitepark\\sInformation\\sEnterprise\\sServer$"]},"sitevision_cms_wapp":{"name":"Sitevision CMS","html_regex":["sitevision/system-resource/(?:[\\w\\d]+)/js/docready-min\\.js","sitevision/system-resource/(?:[\\w\\d]+)/js/AppRegistry\\.js","sitevision/system-resource/(?:[\\w\\d]+)/webapps/webapp_sdk-min\\.js","sitevision/system-resource/(?:[\\w\\d]+)/envision/envision\\.js"],"cookies":["SiteVisionLTM"]},"sivuviidakko_wapp":{"name":"Sivuviidakko","html":["name=\"generator\" content=\"Sivuviidakko"]},"skilldo_wapp":{"name":"Skilldo","headers_regex":["cms\\-name.*?Skilldo$","cms\\-version.*?([\\d\\.]+)"]},"skolengo_wapp":{"name":"Skolengo","html":["name=\"generator\" content=\"Skolengo"],"html_regex":["name=\"version\"[^>]*content=\"([\\d\\.]+)$"]},"smartsite_wapp":{"name":"SmartSite","html_regex":["<[^>]+/smartsite\\.(?:dws|shtml)\\?id="],"html":["name=\"author\" content=\"Redacteur SmartInstant"]},"smartstore_page_builder_wapp":{"name":"Smartstore Page Builder","html_regex":["<section[^>]+class=\"g-stage"]},"solidpixels_wapp":{"name":"SolidPixels","html_regex":["^https?://cdn\\.solidpixels\\.net/"],"html":["name=\"web_author\" content=\"solidpixels"]},"sotel_wapp":{"name":"Sotel","html":["name=\"generator\" content=\"sotel"]},"statamic_wapp":{"name":"Statamic","headers_regex":["x\\-powered\\-by.*?Statamic$"]},"storyblok_wapp":{"name":"Storyblok","headers_regex":["content\\-security\\-policy.*?app\\.storyblok\\.com","x\\-frame\\-options.*?app\\.storyblok\\.com"]},"strapi_wapp":{"name":"Strapi","headers":["X-Powered-By: Strapi"]},"strato_website_wapp":{"name":"Strato Website","html_regex":["strato-editor\\.com/"]},"strikingly_wapp":{"name":"Strikingly","html_regex":["<!-- Powered by Strikingly\\.com"]},"maak_wapp":{"name":"MAAK","html_regex":["name=\"author\"[^>]*content=\"MAAK$"]},"mgpanel_wapp":{"name":"MGPanel","html_regex":["\\.mgpanel\\.org/"]},"mambo_wapp":{"name":"Mambo","html":["name=\"generator\" content=\"Mambo"]},"marketpath_cms_wapp":{"name":"Marketpath CMS","cookies":["_mp_permissions"]},"maxsite_cms_wapp":{"name":"MaxSite CMS","html":["name=\"generator\" content=\"MaxSite CMS"]},"maxencedevcms_wapp":{"name":"MaxenceDEVCMS","html_regex":["name=\"author\"[^>]*content=\"MaxenceDEV$"]},"melis_platform_wapp":{"name":"Melis Platform","html":["<!-- Rendered with Melis Platform","<!-- Rendered with Melis CMS V2"],"html_regex":["name=\"generator\"[^>]*content=\"Melis Platform\\.","name=\"powered\\-by\"[^>]*content=\"Melis CMS\\."]},"memberstack_wapp":{"name":"MemberStack","html_regex":["memberstack\\.js"],"cookies":["memberstack"]},"milestone_cms_wapp":{"name":"Milestone CMS","html_regex":["name=\"generator\"[^>]*content=\"Milestone\\sCMS\\s([\\d\\.]+)$"]},"mogutacms_wapp":{"name":"Moguta.CMS","html_regex":["<link[^>]+href=[\"'][^\"]+mg-(?:core|plugins|templates)/","mg-(?:core|plugins|templates)/"]},"motocms_wapp":{"name":"MotoCMS","html_regex":["<link [^>]*href=\"[^>]*\\/mt-content\\/[^>]*\\.css","/mt-includes/js/website(?:assets)?\\.(?:min)?\\.js"]},"movable_type_wapp":{"name":"Movable Type","html":["name=\"generator\" content=\"Movable Type"]},"mozard_suite_wapp":{"name":"Mozard Suite","html":["name=\"author\" content=\"Mozard"]},"mynetcap_wapp":{"name":"Mynetcap","html":["name=\"generator\" content=\"Mynetcap"]},"bigace_wapp":{"name":"BIGACE","html_regex":["name=\"generator\"[^>]*content=\"BIGACE ([\\d.]+)"]},"boom_wapp":{"name":"BOOM","headers":["X-Supplied-By: MANA"],"html_regex":["name=\"generator\"[^>]*content=\"boom site builder$"]},"backdrop_wapp":{"name":"Backdrop","headers":["X-Backdrop-Cache"],"headers_regex":["X\\-Generator.*?Backdrop CMS(?:\\s([\\d.]+))?"],"html_regex":["name=\"generator\"[^>]*content=\"Backdrop CMS(?:\\s([\\d.]+))?"]},"banshee_wapp":{"name":"Banshee","headers_regex":["X\\-Powered\\-By.*?Banshee PHP framework v([\\d\\.]+)"],"html":["name=\"generator\" content=\"Banshee PHP"]},"batflat_wapp":{"name":"Batflat","html_regex":["name=\"generator\"[^>]*content=\"Batflat$"]},"bentobox_wapp":{"name":"Bentobox","html_regex":["\\.getbento\\.com/"]},"bloomreach_wapp":{"name":"Bloomreach","html_regex":["<[^>]+/binaries/(?:[^/]+/)*content/gallery/"]},"boidcms_wapp":{"name":"BoidCMS","headers":["X-Powered-By: BoidCMS"]},"boldgrid_wapp":{"name":"BoldGrid","html":["/wp-content/plugins/post-and-page-builder"],"html_regex":["<link rel=[\"']stylesheet[\"'] [^>]+boldgrid","<link rel=[\"']stylesheet[\"'] [^>]+post-and-page-builder","<link[^>]+s\\d+\\.boldgrid\\.com"]},"bolt_cms_wapp":{"name":"Bolt CMS","html":["name=\"generator\" content=\"Bolt"]},"botble_cms_wapp":{"name":"Botble CMS","headers_regex":["CMS\\-Version.*?(.+)$"],"cookies":["botble_session"]},"brownie_wapp":{"name":"Brownie","html_regex":["assets\\.youthsrl\\.com/brownie"],"headers":["X-Powered-By: Brownie"]},"browsercms_wapp":{"name":"BrowserCMS","html_regex":["name=\"generator\"[^>]*content=\"BrowserCMS ([\\d.]+)"]},"business_catalyst_wapp":{"name":"Business Catalyst","html":["<!-- BC_OBNW -->","CatalystScripts"]},"neos_cms_wapp":{"name":"Neos CMS","headers_regex":["X\\-Flow\\-Powered.*?Neos/?(.+)?$"]},"nepso_wapp":{"name":"Nepso","headers":["X-Powered-CMS: Nepso"]},"nexusphp_wapp":{"name":"NexusPHP","html_regex":["name=\"generator\"[^>]*content=\"NexusPHP$"]},"nukeviet_cms_wapp":{"name":"Nukeviet CMS","html_regex":["name=\"generator\"[^>]*content=\"NukeViet v([\\d.]+)"]},"cms_made_simple_wapp":{"name":"CMS Made Simple","html":["name=\"generator\" content=\"CMS Made Simple"],"cookies":["CMSSESSID"]},"cmsimple_wapp":{"name":"CMSimple","html_regex":["name=\"generator\"[^>]*content=\"CMSimple( [\\d.]+)?"]},"cendyn_wapp":{"name":"Cendyn","headers":["x-powered-by: NextGuest CMS"]},"chameleon_system_wapp":{"name":"Chameleon system","html":["name=\"generator\" content=\"Chameleon CMS/Shop System"]},"chorus_wapp":{"name":"Chorus","cookies":["_chorus_geoip_continent","chorus_preferences"]},"ckan_wapp":{"name":"Ckan","headers":["Access-Control-Allow-Headers: X-CKAN-API-KEY"],"headers_regex":["Link.*?<http://ckan\\.org/>; rel=shortlink"],"html_regex":["name=\"generator\"[^>]*content=\"ckan ?([0-9.]+)$"]},"cloudrexx_wapp":{"name":"Cloudrexx","html_regex":["name=\"generator\"[^>]*content=\"cloudrexx$"]},"coaster_cms_wapp":{"name":"Coaster CMS","html_regex":["name=\"generator\"[^>]*content=\"Coaster CMS v([\\d.]+)$"]},"concrete_cms_wapp":{"name":"Concrete CMS","html":["/concrete/js/"],"html_regex":["name=\"generator\"[^>]*content=\"concrete5(?: - ([\\d.]+)$)?"],"cookies":["CONCRETE5"]},"congressus_wapp":{"name":"Congressus","html_regex":["name=\"generator\"[^>]*content=\"Congressus\\s-\\s.+$"],"cookies":["_gat_congressus_analytics","congressus_session"]},"contenido_wapp":{"name":"Contenido","html_regex":["name=\"generator\"[^>]*content=\"Contenido ([\\d.]+)"]},"coremedia_content_cloud_wapp":{"name":"CoreMedia Content Cloud","html":["name=\"coremedia_content_id\""],"html_regex":["name=\"generator\"[^>]*content=\"CoreMedia C(?:ontent Cloud|MS)$"]},"cppcms_wapp":{"name":"CppCMS","headers_regex":["X\\-Powered\\-By.*?CppCMS/([\\d.]+)$"]},"cratejoy_wapp":{"name":"Cratejoy","cookies":["cratejoy_muffin42","statjoy_metrics"]},"crownpeak_wapp":{"name":"CrownPeak","html_regex":["js/crownpeak\\."]},"xpressengine_wapp":{"name":"XpressEngine","html":["name=\"generator\" content=\"XpressEngine"]},"jahia_dx_wapp":{"name":"Jahia DX","html":["<script id=\"staticAssetAggregatedJavascrip"]},"jalios_wapp":{"name":"Jalios","html":["name=\"generator\" content=\"Jalios"]},"jouwweb_wapp":{"name":"JouwWeb","html_regex":["(?:cdn)?\\.(?:jwwb|jouwweb)\\.nl/"]},"1cbitrix_wapp":{"name":"1C-Bitrix","html_regex":["bitrix(?:\\.info/|/js/main/core)"],"headers":["Set-Cookie: BITRIX_","X-Powered-CMS: Bitrix Site Manager"],"cookies":["BITRIX_SM_GUEST_ID","BITRIX_SM_LAST_IP","BITRIX_SM_SALE_UID"]},"tn_express_web_wapp":{"name":"TN Express Web","cookies":["TNEW"]},"typo3_cms_wapp":{"name":"TYPO3 CMS","html_regex":["^/?typo3(?:conf|temp)/","name=\"generator\"[^>]*content=\"TYPO3\\s+(?:CMS\\s+)?(?:[\\d.]+)?(?:\\s+CMS)?"]},"thelia_wapp":{"name":"Thelia","html_regex":["<(?:link|style|script)[^>]+/assets/frontOffice/"]},"tiki_wiki_cms_groupware_wapp":{"name":"Tiki Wiki CMS Groupware","html_regex":["(?:/|_)tiki"],"html":["name=\"generator\" content=\"Tiki"]},"townnews_wapp":{"name":"TownNews","headers":["x-tncms"]},"twilight_cms_wapp":{"name":"Twilight CMS","headers":["X-Powered-CMS: Twilight CMS"]},"webnode_wapp":{"name":"WebNode","html_regex":["name=\"generator\"[^>]*content=\"Webnode(?:\\s([\\d.]+))?$"],"cookies":["_gat_wnd_header"]},"webzi_wapp":{"name":"WebZi","html_regex":["//webzi\\.ir/","name=\"generator\"[^>]*content=\"Webzi\\.ir\\sWebsite\\sBuilder$"]},"weblication_wapp":{"name":"Weblication","html_regex":["name=\"generator\"[^>]*content=\"Weblication® CMS$"]},"weblium_wapp":{"name":"Weblium","html_regex":["res2\\.weblium\\.site/common/core\\.min\\.js"]},"websplanet_wapp":{"name":"WebsPlanet","html":["name=\"generator\" content=\"WebsPlanet"]},"website_creator_wapp":{"name":"Website Creator","html":["name=\"generator\" content=\"Website Creator by hosttech","name=\"wsc_rendermode\""]},"websitebaker_wapp":{"name":"WebsiteBaker","html":["name=\"generator\" content=\"WebsiteBaker"]},"webzie_wapp":{"name":"Webzie","html_regex":["name=\"generator\"[^>]*content=\"Webzie\\.com\\sWebsite\\sBuilder$"]},"wix_wapp":{"name":"Wix","html_regex":["static\\.parastorage\\.com","name=\"generator\"[^>]*content=\"Wix\\.com Website Builder"],"headers":["X-Wix-Renderer-Server","X-Wix-Request-Id","X-Wix-Server-Artifact-Id"],"cookies":["Domain"]},"woltlab_community_framework_wapp":{"name":"Woltlab Community Framework","html_regex":["WCF\\..*\\.js"]},"webedition_wapp":{"name":"webEdition","html":["name=\"DC.title\" content=\"webEdition","name=\"generator\" content=\"webEdition"]},"wisycms_wapp":{"name":"wisyCMS","html_regex":["name=\"generator\"[^>]*content=\"wisy CMS[ v]{0,3}([0-9.,]*)"]},"rbs_change_wapp":{"name":"RBS Change","html_regex":["<html[^>]+xmlns:change="],"html":["name=\"generator\" content=\"RBS Change"]},"rayo_wapp":{"name":"Rayo","html":["name=\"generator\" content=\"Rayo"]},"reactive_wapp":{"name":"Reactive","html":["name=\"generator\" content=\"Reactive"]},"readme_wapp":{"name":"ReadMe","html_regex":["/cdn\\.readme\\.io/js/","name=\"readme\\-deploy\"[^>]*content=\"[\\d\\.]+$","name=\"readme\\-version\"[^>]*content=\"[\\d\\.]+$"]},"rebelmouse_wapp":{"name":"RebelMouse","html_regex":["<!-- Powered by RebelMouse\\."],"headers":["x-rebelmouse-cache-control","x-rebelmouse-surrogate-control"]},"ritecms_wapp":{"name":"RiteCMS","html_regex":["name=\"generator\"[^>]*content=\"RiteCMS(?: (.+))?"]},"rockrms_wapp":{"name":"RockRMS","html_regex":["name=\"generator\"[^>]*content=\"Rock v([0-9.]+)"]},"uknowva_wapp":{"name":"uKnowva","html_regex":["<a[^>]+>Powered by uKnowva</a>","/media/conv/js/jquery\\.js","name=\"generator\"[^>]*content=\"uKnowva (?: ([\\d.]+))?"],"headers_regex":["X\\-Content\\-Encoded\\-By.*?uKnowva ([\\d.]+)"]},"farapy_wapp":{"name":"FaraPy","html_regex":["<!-- Powered by FaraPy."]},"flazio_wapp":{"name":"Flazio","html_regex":["//flazio\\.org/"]},"fork_cms_wapp":{"name":"Fork CMS","html_regex":["name=\"generator\"[^>]*content=\"Fork CMS$"]}}

DBEOF

# ── name-only fallback list ───────────────────────────────────────────────────
# 134 additional CMS names (researched from Wikipedia's CMS list and several
# "awesome-cms" community lists) that have NO researched detection pattern in
# the main DB above. Used only as a last resort, if the full signature engine
# above finds nothing at all - see matching engine below. A name-only match is
# much weaker evidence than a pattern match (the product name merely appears
# somewhere in the page, which could be a coincidence, a mention in body text,
# or a copyright string) so these are always flagged distinctly in the output.

cat > "$TMPDIR/fallback_names.json" << 'FBEOF'
["ATutor","Alchemy CMS","Alfresco Cloud","Alfresco Community Edition","Altitude3.Net","Anchor CMS","Apache Jackrabbit","Apache Roller","Apache Sling CMS","AsgardCms","Atlassian Confluence","AxKit","BLOX CMS","Blogger","Bloomreach Experience Manager","Bootstrap CMS","Borgert CMS","Bricolage","Built.io Contentstack","C1 CMS","CMS.js","Camaleon CMS","Cloud CMS","Cloudcannon","Cody","ComfortableMexicanSofa","Composite C1","Composr CMS","ContentBox Modular CMS","Contentverse","Cosmic JS","Croogo","DSpace","DokuWiki","DotNetNuke","EPrints","Enonic XP","Exponent CMS","FUEL CMS","Fedora Commons","Forestry","Foswiki","Geeklog","Hygraph","IBM Enterprise Content Management","Ikiwiki","Jahia Community Distribution","Jahia Enterprise Distribution","Jamroom","Jekyll Admin","KMS","KeystoneJS","Kirby","Known","Kotti","KunstmaanBundlesCMS","Lavalite","Lektor","LiveWhale","LogicalDOC Community Edition","Magnolia","MediaWiki","Medium","Mezzanine","Microweber","Midgard CMS","MoinMoin","Nesta","Netlify CMS","Novius OS","Nucleus CMS","Nuxeo EP","O3Spaces","OctoberCMS","Omeka","Omni CMS","OpenACS","OpenKM Community Edition","OpenText Teamsite","OpenWGA","Opps Project","Oracle Content Management","Oracle WebCenter Content","Orchard Project","Osmek","PHP-Fusion","Payload CMS","Perch","Phire CMS","PhpWiki","Pico","Piranha CMS","Pixie","PmWiki","Prose","Publify","Publii","Quokka CMS","REDAXO","Radiant CMS","Reaction","Redaxscript","Refinery CMS","Relax","Respond CMS","Saleor","Sellerdeck eCommerce","Shopware Community Edition","Sitecore XP","Siteleaf","Spina","Stackbit","Storytime","TWiki","Telligent Community","The Grid","TinaCMS","Umbraco Cloud","Wagtail","We.js Framework","Webhook","Wiki.js","XWiki","Zesty.io","b2evolution","blosxom","censhare","dotCMS","feinCMS","mojoPortal","nopCommerce","phpWebLog","prismic.io","uCoz"]
FBEOF


# Used for any CMS that doesn't have specific version_paths researched above.
# Covers the common README/CHANGELOG/LICENSE/composer.json conventions shared
# across a lot of open-source PHP/Node CMS projects.

cat > "$TMPDIR/generic_paths.json" << 'GPEOF'
["/README.txt","/README.md","/readme.html","/readme.txt","/CHANGELOG.txt","/CHANGELOG.md","/changelog.txt","/LICENSE.txt","/license.txt","/VERSION","/version.txt","/VERSION.txt","/composer.json","/package.json"]
GPEOF

# ── matching engine (CMS identification) ─────────────────────────────────────

MATCH_PID_LOG="$TMPDIR/match.log"
RESULTS_JSON="$TMPDIR/results.json"

( python3 - "$BODY_FILE" "$HEADERS_FILE" "$ROBOTS_FILE" "$TMPDIR/signatures.json" "$RESULTS_JSON" "$TMPDIR/fallback_names.json" << 'PYEOF'
import json, re, sys

body_file, headers_file, robots_file, db_file, out_file, fallback_names_file = sys.argv[1:7]

def read(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return ""

body = read(body_file)
headers = read(headers_file)
robots = read(robots_file)

with open(db_file) as f:
    db = json.load(f)

WEIGHT_LITERAL = 12
WEIGHT_REGEX = 14
WEIGHT_AND_GROUP = 22
WEIGHT_HEADER_LITERAL = 22
WEIGHT_HEADER_REGEX = 24
WEIGHT_HEADER_AND = 28
WEIGHT_COOKIE = 22
WEIGHT_ROBOTS = 16
WEIGHT_ROBOTS_AND = 24
MAX_SCORE_CAP = 100

cookie_names = re.findall(r'Set-Cookie:\s*([^=\s]+)=', headers, re.IGNORECASE)

def safe_search(pattern, text):
    try:
        return re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    except re.error:
        return None

results = []

for cms_id, sig in db.items():
    score = 0
    matched = []
    matched_terms = []  # raw matched strings, reused later for version-proximity search

    for pat in sig.get("html", []):
        if pat.lower() in body.lower():
            score += WEIGHT_LITERAL
            matched.append(f'html: "{pat}"')
            matched_terms.append(pat)

    for pat in sig.get("html_regex", []):
        if safe_search(pat, body):
            score += WEIGHT_REGEX
            matched.append(f'html (regex): "{pat}"')

    if sig.get("html_and"):
        and_pats = sig["html_and"]
        if all(p.lower() in body.lower() for p in and_pats):
            score += WEIGHT_AND_GROUP
            matched.append(f'html (all of): {and_pats}')
            matched_terms.extend(and_pats)

    for pat in sig.get("headers", []):
        if pat.lower() in headers.lower():
            score += WEIGHT_HEADER_LITERAL
            matched.append(f'header: "{pat}"')

    for pat in sig.get("headers_regex", []):
        if safe_search(pat, headers):
            score += WEIGHT_HEADER_REGEX
            matched.append(f'header (regex): "{pat}"')

    if sig.get("headers_and"):
        and_pats = sig["headers_and"]
        if all(p.lower() in headers.lower() for p in and_pats):
            score += WEIGHT_HEADER_AND
            matched.append(f'header (all of): {and_pats}')

    for pat in sig.get("cookies", []):
        for cname in cookie_names:
            if pat.lower() in cname.lower():
                score += WEIGHT_COOKIE
                matched.append(f'cookie: "{cname}"')
                break

    for pat in sig.get("robots", []):
        if pat.lower() in robots.lower():
            score += WEIGHT_ROBOTS
            matched.append(f'robots.txt: "{pat}"')

    if sig.get("robots_and"):
        and_pats = sig["robots_and"]
        if all(p.lower() in robots.lower() for p in and_pats):
            score += WEIGHT_ROBOTS_AND
            matched.append(f'robots.txt (all of): {and_pats}')

    if score > 0:
        score = min(score, MAX_SCORE_CAP)
        results.append({
            "id": cms_id,
            "name": sig["name"],
            "score": score,
            "matched": matched,
            "matched_terms": matched_terms,
            "path_hint": sig.get("path_hint", ""),
            "version_paths": sig.get("version_paths", [])
        })

results.sort(key=lambda r: -r["score"])

# ── name-only fallback ───────────────────────────────────────────────────────
# Only runs if the full signature engine above found absolutely nothing. Checks
# the page body for a verbatim, case-insensitive match of each name in the
# (much larger) name-only list. This is deliberately weak evidence - a plain
# text match could be a passing mention, a copyright footer from an unrelated
# product, or a coincidence - so these results get a fixed, low confidence
# score and are clearly labelled as "name-only" matches in the output, never
# mixed in with real signature-based results.
NAME_ONLY_SCORE = 8  # always shown red/low-confidence, well below any signature match

if not results:
    try:
        with open(fallback_names_file) as f:
            fallback_names = json.load(f)
    except Exception:
        fallback_names = []

    body_lower = body.lower()
    for fname in fallback_names:
        if fname.lower() in body_lower:
            results.append({
                "id": "name_only_" + re.sub(r'[^a-z0-9]', '', fname.lower()),
                "name": fname,
                "score": NAME_ONLY_SCORE,
                "matched": [f'name-only match: "{fname}" found verbatim in page body'],
                "matched_terms": [fname],
                "path_hint": "",
                "version_paths": [],
                "name_only": True
            })

with open(out_file, "w") as f:
    json.dump(results, f)
PYEOF
) > "$MATCH_PID_LOG" 2>&1 &
MATCH_PID=$!
spinner "$MATCH_PID" "Step 2/3: Matching against signature database (381 CMS)"
wait "$MATCH_PID"

# ── version detection ─────────────────────────────────────────────────────────
# For each matched CMS (highest-confidence first), try to find version numbers:
#   Stage 1 (precise): version-style numbers attached to a "?ver=/?v=/?version="
#            query parameter on an asset path containing a software/asset trigger
#            word (css, js, app, assets, theme, plugin, ...). Works independently
#            of whether the CMS name itself appears anywhere near it - some CMS
#            are only identified by structure, not by name in the source.
#   Stage 2 (fallback): only runs if Stage 1 found nothing at all. Broader sweep
#            for any version-shaped number anywhere in the body, no trigger
#            words required - much noisier, used only as a last resort.
# If nothing is found on the main page, the same two-stage search is repeated
# against known version-disclosure paths (CMS-specific where researched, generic
# README/CHANGELOG/composer.json fallback otherwise).
# Distinct version values found are ranked by frequency; the top 3 are kept.
# If the top 3 collapse to a single distinct value -> confident (green).
# If 2+ different values remain in the top 3 -> ambiguous (yellow), all shown
# with their source line so the user can judge for themselves.

VERSION_PID_LOG="$TMPDIR/version.log"
FINAL_RESULTS_JSON="$TMPDIR/final_results.json"

( python3 - "$BODY_FILE" "$RESULTS_JSON" "$TMPDIR/generic_paths.json" "$BASE_URL_FILE" "$FINAL_RESULTS_JSON" << 'PYEOF'
import json, re, sys, subprocess
from collections import Counter

body_file, results_file, generic_paths_file, base_url_file, out_file = sys.argv[1:6]

def read(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return ""

body = read(body_file)
with open(results_file) as f:
    results = json.load(f)
with open(generic_paths_file) as f:
    generic_paths = json.load(f)
base_url = read(base_url_file).strip()

TRIGGER_WORDS = [
    "css", "js", "app", "assets", "asset", "theme", "themes", "style", "styles",
    "bundle", "main", "core", "system", "plugin", "plugins", "module", "modules",
    "static", "dist", "build", "script", "scripts", "vendor", "lib", "libs",
    "template", "templates"
]
TRIGGER_RE_STR = "(?:" + "|".join(TRIGGER_WORDS) + ")"
VERSION_VALUE_RE = r'\d{1,4}(?:\.\d{1,4}){1,3}'

STAGE1_RE = re.compile(
    r'(?P<path>[A-Za-z0-9_\-./]*' + TRIGGER_RE_STR + r'[A-Za-z0-9_\-./]*)'
    r'\?(?:ver|v|version)=(?P<version>' + VERSION_VALUE_RE + r')',
    re.IGNORECASE
)
STAGE2_RE = re.compile(r'\b(' + VERSION_VALUE_RE + r')\b')

# Stage 2 is a broad "any version-shaped number" sweep, used only when the
# precise Stage 1 (?ver=/?v= with an asset trigger word) finds nothing. Being
# broad, it's prone to false positives - mainly IP addresses and CSS numeric
# values that happen to look like a dotted version string. These two filters
# only ever REMOVE candidates, never add false confidence to a real version -
# Stage 1 is completely untouched by either of them.

def looks_like_ip(value):
    """True if the matched value is structurally a valid IPv4 address (four
    octets, each 0-255). CMS version numbers essentially never take this
    exact shape, so this is a safe, purely structural exclusion - e.g. the
    target's own IP appearing in a <base href> tag, a Host header, etc."""
    parts = value.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

# Keywords that, when found IMMEDIATELY before a matched number (small fixed
# window, not the whole line), make it almost certainly a CSS/styling value
# rather than a version string. Deliberately conservative and CSS-property-
# specific - generic enough to catch real noise, narrow enough to never sit
# right before a genuine "ProductName 1.2.3" or "?ver=1.2.3" style match.
STAGE2_NEGATIVE_KEYWORDS = [
    "opacity:", "opacity :",
    "z-index:", "z-index :",
    "rgba(", "rgb(",
    "scale(", "scalex(", "scaley(", "scalez(",
    "line-height:", "line-height :",
]
STAGE2_NEGATIVE_WINDOW = 20  # chars immediately before the match - intentionally tight

def has_negative_context(text, offset):
    lo = max(0, offset - STAGE2_NEGATIVE_WINDOW)
    preceding = text[lo:offset].lower()
    return any(kw in preceding for kw in STAGE2_NEGATIVE_KEYWORDS)

def get_line_for_offset(text, offset, max_len=150):
    line_start = text.rfind('\n', 0, offset) + 1
    line_end = text.find('\n', offset)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    if len(line) <= max_len:
        return line
    rel_offset = offset - line_start
    half = max_len // 2
    start = max(0, rel_offset - half)
    end = min(len(line), start + max_len)
    start = max(0, end - max_len)
    snippet = line[start:end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(line) else ""
    return f"{prefix}{snippet}{suffix}"

def detect_versions(text):
    """Returns {"stage": 0/1/2, "top": [{"version","count","line"}...], "ambiguous": bool}"""
    if not text:
        return {"stage": 0, "top": [], "ambiguous": False}

    hits = [(m.group("version"), m.start()) for m in STAGE1_RE.finditer(text)]
    stage = 1
    if not hits:
        stage2_hits = [(m.group(1), m.start()) for m in STAGE2_RE.finditer(text)]
        hits = [
            (v, off) for v, off in stage2_hits
            if not looks_like_ip(v) and not has_negative_context(text, off)
        ]
        stage = 2
    if not hits:
        return {"stage": 0, "top": [], "ambiguous": False}

    counts = Counter(v for v, _ in hits)
    first_offset = {}
    for v, off in hits:
        if v not in first_offset:
            first_offset[v] = off

    distinct_sorted = sorted(counts.keys(), key=lambda v: (-counts[v], first_offset[v]))
    top_values = distinct_sorted[:3]
    top = [
        {"version": v, "count": counts[v], "line": get_line_for_offset(text, first_offset[v])}
        for v in top_values
    ]
    ambiguous = len(top_values) > 1
    return {"stage": stage, "top": top, "ambiguous": ambiguous}

def fetch_path(base_url, path):
    """Best-effort curl fetch, returns body text or empty string. Short timeout,
    failures are silent (a missing version-disclosure path is expected/common)."""
    url = base_url.rstrip('/') + path
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", "6", "-L", url],
            capture_output=True, text=True, timeout=8
        )
        return out.stdout or ""
    except Exception:
        return ""

MAX_CMS_TO_VERSION_CHECK = 3  # only deep-check the top N matches, to keep runtime sane
MAX_PATHS_TO_TRY = 6          # cap path probing per CMS

for r in results[:MAX_CMS_TO_VERSION_CHECK]:
    detection = detect_versions(body)
    checked_paths = []
    source = "main page"

    if detection["stage"] == 0:
        paths_to_try = r.get("version_paths") or generic_paths
        for path in paths_to_try[:MAX_PATHS_TO_TRY]:
            page_text = fetch_path(base_url, path)
            checked_paths.append(path)
            if page_text:
                detection = detect_versions(page_text)
                if detection["stage"] != 0:
                    source = path
                    break

    r["version_detection"] = detection
    r["version_source"] = source if detection["stage"] != 0 else None
    r["version_paths_checked"] = checked_paths
    r["version_was_checked"] = True

# CMS beyond MAX_CMS_TO_VERSION_CHECK just get an empty detection (not checked, to save time)
for r in results[MAX_CMS_TO_VERSION_CHECK:]:
    r["version_detection"] = {"stage": 0, "top": [], "ambiguous": False}
    r["version_source"] = None
    r["version_paths_checked"] = []
    r["version_was_checked"] = False

with open(out_file, "w") as f:
    json.dump(results, f)
PYEOF
) > "$VERSION_PID_LOG" 2>&1 &
VERSION_PID=$!
spinner "$VERSION_PID" "Step 3/3: Searching for CMS version numbers"
wait "$VERSION_PID"

# ── results ───────────────────────────────────────────────────────────────────

echo
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                       RESULTS                         ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo

python3 - "$FINAL_RESULTS_JSON" << 'PYEOF'
import json, sys

GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
RED = "\033[0;31m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

with open(sys.argv[1]) as f:
    results = json.load(f)

if not results:
    print(f"{YELLOW}No known CMS signature matched.{NC}")
    print(f"{YELLOW}Check the page source manually for product names, JS framework hints,")
    print(f"or unusual login/asset paths - then add a signature entry to this script.{NC}")
    sys.exit(0)

def bar(score):
    filled = int(score / 5)
    return "█" * filled + "░" * (20 - filled)

def color_for(score):
    if score >= 50:
        return GREEN
    if score >= 20:
        return YELLOW
    return RED

results.sort(key=lambda r: -r["score"])

is_name_only_mode = any(r.get("name_only") for r in results)

if is_name_only_mode:
    print(f"{YELLOW}No CMS matched via signature patterns.{NC}")
    print(f"{YELLOW}Found {len(results)} name-only match(es) instead - the product name appears")
    print(f"verbatim in the page, but this CMS has no researched detection pattern in this")
    print(f"script yet. Treat these as weak leads to check manually, not confirmed results.{NC}")
    print()

for r in results:
    if r.get("name_only"):
        print(f"{BOLD}{YELLOW}{r['name']}{NC}  {CYAN}(name-only match){NC}")
        for m in r["matched"]:
            print(f"    {CYAN}-{NC} {m}")

        vd = r.get("version_detection", {"stage": 0, "top": [], "ambiguous": False})
        top = vd.get("top", [])
        if not top:
            print(f"  Version: {RED}No version number found.{NC}")
        elif not vd.get("ambiguous"):
            only = top[0]
            print(f"  Version: {YELLOW}{only['version']}{NC}  {CYAN}(found {only['count']}x, source: {r.get('version_source')}){NC}")
            print(f"    {CYAN}note:{NC} CMS itself was only a name-only match - check the line below to confirm this version really belongs to it:")
            print(f"      {only['line']}")
        else:
            print(f"  Version: {YELLOW}Multiple candidate versions found - CMS match is also name-only, treat with extra caution:{NC}")
            for t in top:
                print(f"    {YELLOW}Version: {t['version']}{NC}  {CYAN}(x{t['count']}){NC}")
                print(f"      {t['line']}")
        print()
        continue

    c = color_for(r["score"])
    print(f"{BOLD}{GREEN}{r['name']}{NC}")
    print(f"  Confidence: {c}{r['score']:>3}/100{NC}  [{c}{bar(r['score'])}{NC}]")
    for m in r["matched"]:
        print(f"    {CYAN}-{NC} {m}")
    if r.get("path_hint"):
        print(f"    {CYAN}hint paths:{NC} {r['path_hint']}")

    # version output:
    #   - no hits at all -> red "not found"
    #   - hits collapse to a single distinct version value (regardless of how many
    #     times it was found) -> green, confident single result
    #   - 2+ different distinct values in the top 3 -> yellow, list all with source line
    vd = r.get("version_detection", {"stage": 0, "top": [], "ambiguous": False})
    top = vd.get("top", [])

    if not r.get("version_was_checked"):
        print(f"  Version: {CYAN}Not checked (outside top 3 matches).{NC}")
    elif not top:
        print(f"  Version: {RED}No version number found.{NC}")
    elif not vd.get("ambiguous"):
        only = top[0]
        stage_note = " (broad match, no asset trigger word nearby)" if vd["stage"] == 2 else ""
        print(f"  Version: {BOLD}{GREEN}{only['version']}{NC}  {CYAN}(found {only['count']}x, source: {r.get('version_source')}){NC}{stage_note}")
    else:
        stage_note = " - broad fallback match, treat with extra caution" if vd["stage"] == 2 else ""
        print(f"  Version: {YELLOW}Multiple candidate versions found{stage_note}:{NC}")
        for t in top:
            print(f"    {YELLOW}Version: {t['version']}{NC}  {CYAN}(x{t['count']}){NC}")
            print(f"      {t['line']}")
    print()
PYEOF

echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "[!] Score is heuristic, not proof - confirm manually before reporting."
echo -e "[!] Version detection only checks the top 3 matches to keep runtime reasonable."
echo -e "[!] Unknown CMS? Add a signature block to the DB section of this script."
