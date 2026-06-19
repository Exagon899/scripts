#!/usr/bin/env bash
# cmsdetect.sh - generic CMS/web-framework fingerprinting tool
# Matches HTML body, headers, and cookies against an embedded signature DB.
# No external DB file or API needed - everything ships in this script.
#
# Signature database derived in large part from CMSeeK (GPLv3, Copyright 2018-2020
# Tuhinshubhra), converted from its cmseekdb/{cmss,sc,header,robots}.py source files.
# Original project: https://github.com/Tuhinshubhra/CMSeeK
# A handful of additional signatures (e.g. Cockpit CMS, Strapi, Directus, ProcessWire,
# CouchCMS) were added by hand for CMS not present in CMSeeK's database.
# Because this script embeds and redistributes GPLv3-derived signature data, this
# script as a whole is licensed under GPLv3 - see https://www.gnu.org/licenses/gpl-3.0.html

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

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 -L "$URL" 2>/dev/null || echo "000")
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
}

FETCH_PID_LOG="$TMPDIR/fetch.log"
( fetch ) > "$FETCH_PID_LOG" 2>&1 &
FETCH_PID=$!
spinner "$FETCH_PID" "Step 1/2: Fetching target (body, headers, robots.txt)"
wait "$FETCH_PID"

BODY_FILE="$TMPDIR/body.html"
HEADERS_FILE="$TMPDIR/headers.txt"
ROBOTS_FILE="$TMPDIR/robots.txt"

[ -f "$BODY_FILE" ] || touch "$BODY_FILE"
[ -f "$HEADERS_FILE" ] || touch "$HEADERS_FILE"
[ -f "$ROBOTS_FILE" ] || touch "$ROBOTS_FILE"

# ── embedded signature DB (JSON) ─────────────────────────────────────────────
# 172 CMS total. Most signatures converted from CMSeeK (GPLv3) - see header comment.
# Format per CMS entry:
#   html / html_regex / html_and   - matched against page body (literal / regex / AND-all-must-match)
#   headers / headers_regex / headers_and - matched against response headers
#   robots / robots_and            - matched against robots.txt
#   cookies                        - matched against Set-Cookie header names
# To add your own findings (e.g. an unknown CMS from a box), add a new JSON object
# below following the same structure - no other code changes needed.

cat > "$TMPDIR/signatures.json" << 'DBEOF'
{"wp":{"name":"WordPress","html":["/wp-content/","/wp-include/"],"headers":["/wp-json/"],"robots":["Disallow: /wp-admin/","Allow: /wp-admin/admin-ajax.php"]},"mg":{"name":"Magento","html":["/skin/frontend/","x-magento-init"]},"blg":{"name":"Blogger By Google","html":["https://www.blogger.com/static/"]},"lj":{"name":"LiveJournal","html":["ic.pics.livejournal.com"]},"tdc":{"name":"3dCart","html":["END: 3dcart stats"]},"apos":{"name":"Apostrophe CMS","html":["href=\"/apos-minified/"]},"abc":{"name":"Adobe Business Catalyst","html":["href=\"/CatalystStyles/"]},"dru":{"name":"Drupal","html":["/misc/drupal.js"],"headers":["X-Drupal-","19 Nov 1978 05"],"robots":["Allow: /core/*.css$","Disallow: /index.php/user/login/","Disallow: /web.config"]},"joom":{"name":"Joomla","html":["css/joomla.css"],"headers":["Expires: Wed, 17 Aug 2005 00:00:00 GMT"],"robots_and":["If the Joomla site is installed","Disallow: /administrator/"]},"oc":{"name":"OpenCart","html":["Powered By <a href=\"http://www.opencart.com\">OpenCart","\"catalog/view/javascript/jquery/swiper/css/opencart.css\"","index.php?route="]},"xoops":{"name":"XOOPS","html":["/xoops.js","xoops_redirect"],"robots_and":["Disallow: /kernel/","Disallow: /language/","Disallow: /templates_c/"]},"tilda":{"name":"Tilda CMS","html":["tildacdn.com"],"robots":["Disallow: /tilda"]},"wolf":{"name":"Wolf CMS","html":["Wolf Default RSS Feed"]},"ushahidi":{"name":"Ushahidi","html":["/ushahidi.js","alt=\"Ushahidi\""],"headers":["Set-Cookie: ushahidi"]},"wgui":{"name":"WebGUI","html":["getWebguiProperty"]},"tidw":{"name":"TiddlyWiki","html":["title: \"TiddlyWiki\"","TiddlyWiki created by Jeremy Ruston,"]},"sqm":{"name":"Squiz Matrix","html":["Running Squiz Matrix"],"headers":["Set-Cookie: SQ_SYSTEM_SESSION","squizedge.net"]},"spin":{"name":"Spin CMS","html":["assets.spin-cdn.com"],"headers":["spincms"]},"sdev":{"name":"solodev","html":["content=\"Solodev\" name=\"author\""],"headers":["solodev_session"]},"snews":{"name":"sNews","html":["content=\"sNews"]},"score":{"name":"Sitecore","html":["/api/sitecore/"],"headers":["SC_ANALYTICS_GLOBAL_COOKIE"],"robots":["Disallow: /sitecore","Disallow: /sitecore_files","Disallow: /sitecore modules"]},"sim":{"name":"SIMsite","html":["simsite/"]},"spb":{"name":"Simpl\u00e9bo","html":["simplebo.net/"],"headers":["X-ServedBy: simplebo","_simplebo_tool_session"]},"silva":{"name":"Silva CMS","html":["/silvatheme"]},"spity":{"name":"Serendipity","html":["serendipityQuickSearchTermField ","\"serendipity_","serendipity["],"headers":["X-Blog: Serendipity","Set-Cookie: serendipity[","Set-Cookie: s9y_"]},"slcms":{"name":"SeamlessCMS","html":["Published by Seamless.CMS.WebUI"],"headers":["Set-Cookie: SEAMLESS_IDENTIFIER"]},"rock":{"name":"Rock RMS","html":["rock-config-trigger","rock-config-cancel-trigger"]},"rcms":{"name":"RCMS","html":["/rcms-f-production."]},"quick":{"name":"Quick.Cms","html":["CMS by Quick.Cms","Powered by Quick.Cart"]},"dle":{"name":"DataLife Engine","html":["DataLife Engine","dle_js.js"]},"rcube":{"name":"RoundCube Webmail","html":["Roundcube Webmail","rcube_webmail"]},"bitrix":{"name":"Bitrix","html":["bitrix","Bitrix"],"headers":["X-Powered-CMS: Bitrix Site Manager"],"robots":["Disallow: /bitrix/"]},"pcore":{"name":"Pimcore","html":["\"pimcore_"],"headers":["X-Powered-By: pimcore"]},"percms":{"name":"Percussion CMS","html":["xmlns:perc","cm/css/perc_decoration.css"]},"pblue":{"name":"PencilBlue","html":["PencilBlueController","\"pencilblueApp\""],"headers":["x-powered-by: PencilBlue"]},"ophal":{"name":"Ophal","html":["/libraries/ophal.js"],"headers":["x-powered-by: Ophal"]},"sfy":{"name":"Sitefinity","html":["Sitefinity/WebsiteTemplates"]},"zyro":{"name":"Zyro","html":["assets.zyrosite.com"],"headers":["x-powered-by: Zyro.com"]},"otwsm":{"name":"OpenText WSM","html":["published by Open Text Web Solutions"]},"ocms":{"name":"OpenCms","html":["/opencms/export/"],"headers":["Server: OpenCms"]},"odoo":{"name":"Odoo","html":["odoo.session_info","var odoo ="],"headers":["X-Odoo-"]},"share":{"name":"Microsoft Sharepoint","html":["_spBodyOnLoadWrapper","_spPageContextInfo","_spFormOnSubmitWrapper"],"headers":["X-SharePointHealthScore","SPIisLatency","SPRequestGuid","MicrosoftSharePointTeamServices","SPRequestDuration"]},"octcms":{"name":"October CMS","html":["/storage/app/media/"],"headers":["october_session"]},"mura":{"name":"Mura CMS","html":["mura.min.css","/plugins/Mura"],"headers":["Generator: Mura CMS"]},"moto":{"name":"Moto CMS","html":["mt-content/","moto-website-style"],"robots":["Disallow: /*mt-content*","Disallow: /mt-includes/"]},"mnet":{"name":"Mono.net","html":["mono_donottrack","monotracker.js ","_monoTracker"]},"modx":{"name":"MODX","html":["Powered by MODX</a>"],"headers":["X-Powered-By: MODX"]},"methd":{"name":"Methode","html":["siteCMS:methode\"","\"contentOriginatingCMS=Methode\"","Methode tags version","/r/PortalConfig/common/assets/"]},"lscms":{"name":"LiveStreet CMS","html":["var LIVESTREET_SECURITY_KEY"]},"koken":{"name":"Koken","html":["/koken.js","data-koken-internal"]},"jimdo":{"name":"Jimdo","html":["jimdo_layout_css","var jimdoData","isJimdoMobileApp"],"headers":["X-Jimdo-"]},"ibit":{"name":"Indexhibit","html":["<!-- you must provide a link to Indexhibit","\"Built with <a href=http://www.indexhibit.org/>Indexhibit\"","ndxz-studio/site","ndxzsite/"],"headers":["Set-Cookie: ndxz_"]},"wflow":{"name":"Webflow CMS","html":["<!-- webflow css -->","css/webflow.css","js/webflow.js"]},"jcms":{"name":"Jalios JCMS","html":["css/jalios/core/","js/jalios/core/","jalios:ready"],"headers":["X-Jcms-Ajax-Id"],"robots":["Disallow: /jcmsplugin/"]},"impage":{"name":"ImpressPages CMS","html":["ip_themes/","ip_libs/","ip_cms/"],"headers_regex":["Set-Cookie: ses(\\d+)="],"robots":["Disallow: /ip_cms/","ip_backend_frames.php","ip_backend_worker.php"]},"hotaru":{"name":"Hotaru CMS","html":["/css_js_cache/hotaru_css","hotaruFooterImg","/css_js_cache/hotaru_js"]},"hippo":{"name":"HIPPO CMS","html":["binaries/content/gallery/"],"html_regex":["binaries/(.*?)/content/gallery/"]},"phpn":{"name":"PHP Nuke","html":["PHP-Nuke Copyright \u00a9","PHP-Nuke theme by"]},"flex":{"name":"FlexCMP","html":["FlexCMP - CMS per Siti Accessibili","/flex/TemplatesUSR/","FlexCMP - Digital Experience Platform (DXP)"],"headers":["X-Powered-By: FlexCMP","X-Flex-Tag:","X-Flex-Lang:","X-Flex-Lastmod:","X-Flex-Community:","X-Flex-Evstart"],"robots":["Disallow: /flex/tmp/","flex/Logs/"]},"ezpu":{"name":"eZ Publish","html":["copyright\" content=\"eZ Systems\"","ezcontentnavigationpart","ezinfo/copyright"],"headers":["X-Powered-By: eZ Publish","Set-Cookie: eZSESSID"]},"e107":{"name":"e107","html":["e107_files/e107.js","e107_themes/","e107_plugins/"],"headers":["X-Powered-By: e107","Set-Cookie: SESSE107COOKIE"],"robots":["Disallow: /e107_admin/","e107_handlers","e107_files/cache"]},"dnn":{"name":"DNN Platform","html":["<!-- DNN Platform"," by DNN Corporation -->","DNNROBOTS","js/dnncore.js?","dnn_ContentPane","js/dnn.js?"],"headers":["Set-Cookie: dnn_IsMobile","DNNOutputCache","DotNetNuke"]},"phpbb":{"name":"phpBB","html":["phpBBstyle","phpBBMobileStyle","style_cookie_settings"],"html_regex":["Powered by (.*?)phpBB","copyright(.*?)phpBB Group"],"headers_regex":["Set-Cookie: phpbb(.*?)="]},"dede":{"name":"DEDE CMS","html":["dede_fields","dede_fieldshash","DedeAjax","DedeXHTTP","include/dedeajax2.js","css/dedecms.css"],"robots":["Disallow: /plus/ad_js.php","Disallow: /plus/erraddsave.php","Disallow: /plus/posttocar.php","Disallow: /plus/disdls.php","Disallow: /plus/mytag_js.php","Disallow: /plus/stow.php"]},"orchd":{"name":"Orchard CMS","html":["/Orchard.jQuery/","orchard.themes","orchard-layouts-root"],"headers":["X-Generator: Orchard"]},"cbox":{"name":"ContentBox","html":["modules/contentbox/themes/"],"headers":["X-Powered-By: ContentBox","Set-Cookie: LIGHTBOXSESSION"],"robots":["modules/contentbox/themes/"]},"conful":{"name":"Contentful","html":["data-contentful",".contentful.com/",".ctfassets.net/"]},"contensis":{"name":"contensis","html":["Contensis.current","ContensisSubmitFromTextbox","ContensisTextOnly"]},"contao":{"name":"Contao CMS","html":["system/cron/cron.txt"],"robots":["Disallow: /contao/"]},"bboard":{"name":"Burning Board","html":["/burningBoard.css","wcf/style/"],"html_regex":["(a href\\=\"http\\://www\\.woltlab\\.com\"|Forum Software|Forensoftware)(.*?)Burning Board(.*?)\\</strong\\>"],"headers_regex":["Set-Cookie: wcf(.*?)_cookieHash="]},"con5":{"name":"Concrete5 CMS","html":["/concrete/images","/concrete/css","/concrete/js"],"html_regex":["CCM_(.*?)(_|)(MODE|URL|PATH|FILENAME|REL|CID)"],"headers":["Set-Cookie: CONCRETE5"],"robots":["Disallow: /concrete"]},"discrs":{"name":"discrs","html":["discourse_theme_id","discourse_current_homepage"]},"discuz":{"name":"Discuz!","html":["discuz_uid","discuz_tips","content=\"Discuz! Team and Comsenz UI Team\""],"robots_and":["uc_client","uc_server","forum.php?mod=redirect*"]},"flarum":{"name":"Flarum","html":["flarum-loading","flarum/app"],"headers":["Set-Cookie: flarum_session="]},"ipb":{"name":"IP.Board community forum","html":["/* IP.Board","js/ipb.js","js/ipb.lang.js","ips_usernameand ips_password"],"html_regex":["invisioncommunity\\.com(.*?)Powered by Invision Community","ipb\\.(vars|templates|lang)\\[(.*?)=(.*?)\\</script\\>"],"headers":["IPSSessionFront","ipbWWLmodpids","ipbWWLsession_id"]},"minibb":{"name":"miniBB","html":["bb_default_style.css","name=\"URL\" content=\"http://www.minibb.net/\""],"html_regex":["(powered by|http\\://www\\.miniBB\\.net)(.*?)(miniBB|miniBB forum software)"]},"mybb":{"name":"MyBB","html":["var MyBBEditor"],"html_regex":["(Powered By|href\\=\"https\\://www\\.mybb\\.com\")(.*?)(MyBB|MyBB Group)\\</a\\>"],"headers_regex":["Set-Cookie: mybb\\[(.*?)\\]="]},"nodebb":{"name":"NodeBB","html":["/assets/nodebb.min.js","/plugins/nodebb-"],"html_regex":["Powered by(.*?)NodeBB\\</a\\>"],"headers":["X-Powered-By: NodeBB"]},"punbb":{"name":"PunBB","html":["PUNBB.env","typeof PUNBB ==="],"html_regex":["Powered by(.*?)PunBB\\</a\\>"]},"smf":{"name":"Simple Machines Forum","html":["Powered by SMF"],"html_regex":["var smf_(theme_url|images_url|scripturl) \\=(.*?)\\</script\\>"]},"vanilla":{"name":"Vanilla Forums","html":["vanilla_discussions_index","vanilla_categories_index"],"html_regex":["applications/vanilla/(.*?)\\.js"],"headers":["X-Garden-Version: Vanilla","Maybe you should be reading this instead: https://www.vanillaforums.com/en/careers"]},"xf":{"name":"XenForo","html":["Forum software by XenForo&trade;","<html id=\"XenForo\"","css.php?css=xenforo"],"headers":["Set-Cookie: xf_session=","Set-Cookie: xf_csrf="]},"xmb":{"name":"XMB","html":["<!-- Powered by XMB","<!-- The XMB Group -->","Powered by XMB"],"headers_regex":["Set-Cookie: xmblv(a|b)=(\\d.*?)\n"]},"yabb":{"name":"YaBB (Yet another Bulletin Board)","html":["yabbfiles/"],"headers_regex":["Set-Cookie: (YaBBusername=|YaBBpassword=|YaBBSession|Y2User-(\\d.*?)|Y2Pass-(\\d.*?)|Y2Sess-(\\d.*?))="]},"aef":{"name":"Advanced Electron Forum","html":["Powered By AEF"],"html_regex":["aefonload(.*?)\\</script\\>"],"headers":["[aefsid]"]},"fudf":{"name":"FUDforum","html":["Powered by: FUDforum"],"headers":["Set-Cookie: fud_session_"]},"phorum":{"name":"Phorum","html":["<div id=\"phorum\">"],"headers":["Set-Cookie: phorum_session"]},"yaf":{"name":"Yet Another Forum (YAF)","html":["\"YafHead"],"html_regex":["\\>Powered by YAF\\.NET(.*?)\\</a\\>"]},"nnf":{"name":"NoNonsense Forum","html":["<!-- NoNonsense Forum"],"html_regex":["Powered by(.*?)NoNonsense Forum\\</a\\>"]},"mvnf":{"name":"mvnForum","html":["/mvnplugin/mvnforum/"],"html_regex":["Powered by(.*?)mwForum(.*?)Markus Wichitill","Powered by(.*?)mvnForum(.*?)\\</a\\>"]},"aspf":{"name":"AspNetForum","html":["aspnetforum.css\"","_AspNetForumContentPlaceHolder"],"html_regex":["Powered by(.*?)AspNetForum(.*?)(\\</a\\>|\\</span\\>)"]},"jf":{"name":"JForum","html":["jforum/templates/"],"html_regex":["Powered by(.*?)JForum(.*?)\\</a\\>"]},"abuy":{"name":"Afterbuy","html":["This OnlineStore is brought to you by ViA-Online GmbH Afterbuy."],"robots":["Disallow: /AfterbuySrcProxy.aspx","Disallow: /afterbuy.asmx","Disallow: /afterbuySrc.asmx"]},"arstta":{"name":"Arastta","html":["/arastta.js"],"headers":["X-Arastta"]},"bizw":{"name":"Bizweb","html":["<script src='//bizweb.dktcdn.net"],"html_regex":["var Bizweb \\=(.*?)\\</script\\>"]},"cloudc":{"name":"CloudCart","html":["cloudcart\",\"title"],"html_regex":["\\<meta name\\=(.*?)author(.*?)CloudCart LLC(.*?)\\>"]},"cmshop":{"name":"ColorMeShop","html":["framework/colormekit.css"],"html_regex":["var Colorme \\=(.*?)\\</script\\>"]},"mdle":{"name":"Moodle","html":["<meta name=\"keywords\" content=\"moodle"],"headers":["Set-Cookie: MoodleSession","Set-Cookie: MOODLEID_"]},"orkis":{"name":"ORKIS Ajaris Websuite","html":["<meta property=\"ajaris:baseURL\"","<meta property=\"ajaris:language\"","<meta property=\"ajaris:ptoken\""]},"cmdia":{"name":"Comandia","html":["window.Comandia = JSON.parse","<script src=\"https://cdn.mycomandia.com/static/shop/common/js/functions.js\"></script>"],"html_regex":["https://cdn.mycomandia.com/uploads/comandia_(.*?)/r/(.*?)//js/(functions|main).js"]},"elcd":{"name":"Elcodi","html":["/bundles/elcodimetric/js/tracker.js"],"html_regex":["<script(.*?)Tracker generator for elcodi bamboo store(.*?)</script>"],"headers":["X-Elcodi:"]},"epgs":{"name":"ePages","html":["de_epages.remotesearch.ui.suggest","require([['de_epages'"],"html_regex":["href=(.*?)/epages/(.*?).sf(.*?)</a>"],"robots":["Disallow: /epages/Site.admin/","Disallow: /epages/*"]},"for3":{"name":"Fortune3","html":["href=\"https://www.fortune3.com/en/siterate/rate.css\""],"html_regex":["Powered by(.*?)Fortune3</a>"]},"btree":{"name":"BigTree CMS","html_regex":["Built on(.*?)bigtreecms.org(.*?)BigTree CMS"],"html_and":["<body class=\"gridlock shifter\">","<div class=\"shifter-page\">"]},"pmoc":{"name":"Proximis Omnichannel","html_and":["list-unstyled","editable-zone"]},"sfcc":{"name":"Salesforce Commerce Cloud","html":["<!-- Demandware Analytics code","<!-- Demandware Apple Pay -->"],"html_regex":["href\\=(.*?)on/demandware.static"],"headers":["Demandware Secure Token","Demandware anonymous cookie","dwpersonalization_","dwanonymous_"],"robots":["demandware.store","demandware.static","demandware.net"]},"sazito":{"name":"Sazito","html":["icons__icons___XoCGh","styles__empty___3WCoC","icons__icon-phone___22Eum"]},"shopatron":{"name":"Shopatron","html":["SHOPATRON-CRAWLER"],"html_regex":["href\\=(.*?)mediacdn.shopatron.com","href\\=(.*?)cdn.shptrn.com"]},"umbraco":{"name":"Umbraco","html":["Umbraco/","umbraco/"],"headers":["X-Umbraco-Version"],"robots":["robots.txt for Umbraco","Disallow: /umbraco","Disallow: /umbraco_client"]},"shoper":{"name":"Shoper","html":["Sklep internetowy Shoper.pl"],"html_regex":["href\\=(.*?)rwd_shoper(|_1)"]},"shopery":{"name":"Shopery","html":["//www.googletagmanager.com/ns.html?id=GTM-N2T2D3"],"html_regex":["(cdn|font).shopery.com/"],"headers":["X-Shopery","This E-commerce is built using Shopery"]},"shopfa":{"name":"ShopFA","html":["shopfa_license"],"html_regex":["href\\=(.*?)cdn.shopfa.com/","href\\=(.*?)cdnfa.com/"],"headers":["X-Powered-By: ShopFA"]},"smartstore":{"name":"Smartstore","html":["/smjslib.js","/smartstore.core.js"],"html_regex":["css/smartstore.(core|theme|modules).css"],"robots_and":["Disallow: /broker","Disallow: /broker/orders"]},"weebly":{"name":"Weebly","html":["_W.configDomain","Weebly.footer"],"html_regex":["weebly-(footer|icon)"],"headers_regex":["X-Host: (.*?)weebly.net"],"robots_and":["Disallow: /ajax","Disallow: /apps"]},"whmcs":{"name":"WHMCS","html":["js/whmcs.js"],"headers":["Set-Cookie: WHMCS"]},"opennemas":{"name":"OpenNemas CMS","html":["OpenNeMaS CMS by Openhost","var u = \"https://piwik.openhost.es/\""],"html_regex":["onm-(new|image|carousel|big|cropped)"],"headers":["X-Powered-By: OpenNemas","Via: Opennemas Proxy Server"],"robots_and":["Disallow: /harming/humans","Disallow: /ignoring/human/orders","Disallow: /harm/to/self"]},"zencart":{"name":"Zen Cart CMS","html":["zenid=","Congratulations! You have successfully installed your Zen Cart","Google Code for ZenCart Google","Powered by ZenCart","sideboxpzen-cart","stylesheet_zen_lightbox.css"],"robots":["Zen Cart doesn't require any","Zen Cart installation","pzen_"]},"ipo":{"name":"IPO CMS","html":["Redak\u010dn\u00ed syst\u00e9m IPO","cdn.antee.cz/","ipo.min.js"],"html_regex":["ipo(pagetext|mainframe|footer|menuwrapper|copyright|header|main|menu|statistics)"],"robots":["Disallow: /*action=personalDataProcessing*"]},"hugo":{"name":"Hugo","html":["Built using HUGO"]},"squarespace":{"name":"Squarespace","html":["This is Squarespace","End of Squarespace Headers"]},"afsto":{"name":"Afosto","html_regex":["('|\")https\\://afosto\\-cdn(.*?)\\.afosto\\.com(.*?)('|\")"],"headers":["X-Powered-By: Afosto","Link: <//afosto-cdn"]},"mcb":{"name":"MercuryBoard","html_regex":["Powered by(.*?)MercuryBoard(.*?)\\</a\\>"]},"myupb":{"name":"myUPB","html_regex":["Powered by myUPB(.*?)\\</a\\>"]},"ubbt":{"name":"UBB.threads","html_regex":["\\>Powered by UBB\\.threads(.*?)\\</a\\>"],"headers":["Set-Cookie: ubbt_"]},"fluxbb":{"name":"FluxBB","html_regex":["Powered by(.*?)FluxBB"]},"dscrs":{"name":"Discourse","html_regex":["Discourse\\.(.*?)\\=(.*?)\\</script\\>"],"headers":["X-Discourse-Route"],"robots_and":["Disallow: /auth/cas","Disallow: /auth/cas/callback"]},"arc":{"name":"Arc Forum","html_regex":["ping\\.src \\= node\\.href(.*?)\\</script\\>"]},"phpc":{"name":"phpCMS","html_regex":["\\.php\\?m\\=(.*?)&c\\=(.*?)&a\\=(.*?)&catid\\="],"robots":["Disallow: /phpcms","robots.txt for PHPCMS"]},"coton":{"name":"Cotonti","html_regex":["Powered by(.*?)Cotonti"]},"bigc":{"name":"BigCommerce","html_regex":["\\<link href\\=(.*?)cdn(\\d).bigcommerce\\.com\\/"],"headers":["set-cookie: fornax_anonymousId="]},"bigw":{"name":"Bigware","html_regex":["\\<a href\\=(.*?)main_bigware_(\\d)\\.php"],"headers":["Set-Cookie: bigwareCsid","Set-Cookie: bigWAdminID"]},"cexec":{"name":"Clientexec","html_regex":["var clientexec \\=(.*?)\\</script\\>","Powered by(.*?)http\\://www\\.clientexec\\.com\\?source\\=poweredby(.*?)\\</a\\>"]},"cosmos":{"name":"Cosmoshop","html_regex":["<script(.*?)cosmoshop_functions.js(.*?)</script>"],"headers":["Set-Cookie: COSMOSHOP_"]},"csc":{"name":"CS Cart","html_regex":[".cm-noscript(.*?)</script>"],"headers_regex":["Set-Cookie: sid_customer_[a-zA-Z0-9]{5}="],"robots_and":["Disallow: /app/","Disallow: /store_closed.html"]},"cubec":{"name":"CubeCart","html_regex":["<link(.*?)cubecart.common.css(.*?)>"]},"abda":{"name":"Al Mubda","html_regex":["<a href(.*?)http://www.almubda.net(.*?)Powered by Al Mubda(.*?)</a>"]},"dweb":{"name":"Dynamicweb","html_regex":["<!--(.*?)Dynamicweb Software(.*?)-->"],"headers":["Set-Cookie: Dynamicweb"],"robots":["Disallow: /*?cartcmd=*"]},"ecc":{"name":"EC-CUBE","html_regex":["<script(.*?)eccube.js(.*?)</script>","<script(.*?)win_op.js(.*?)</script>","<script(.*?)cube.site.js(.*?)</script>"]},"ezpub":{"name":"eZ Publish","html_regex":["<script(.*?)/extension/iagutils/design/ezwebin/(.*?)</script>"],"headers":["X-Powered-By: eZ Publish"],"robots":["Disallow: /Mediatheque/"]},"shopify":{"name":"Shopify","html_regex":["id=(\"|')(shopify-digital-wallet|shopify-features)","href\\=(.*?)cdn.shopify.com/"],"headers":["X-Shopify-Stage","set-cookie: _shopify","Set-Cookie: secure_customer_sig"],"robots":["we use Shopify"],"headers_and":["X-ShopId","X-ShardId"]},"shoptet":{"name":"Shoptet","html_regex":["href\\=(.*?)cdn.myshoptet.com/","content=\"Shoptet.sk\"","var shoptet="],"headers":["SRV_ID=shoptet"],"robots_and":["diskuse","wysiwyg","dotaz","hodnoceni"]},"spree":{"name":"Spree","html_regex":["src=(.*?)spree/(products|brands)","Spree.(api_key|routes|translations)"],"headers":["Set-Cookie: _spree_store_session"],"robots":["spree/products/"]},"brightspot":{"name":"Brightspot CMS","html_regex":["meta name\\=(\"|')brightspot.(contentId|cached)","href=(\"|')brightspotcdn"],"headers":["X-Powered-By: Brightspot"]},"amiro":{"name":"Amiro.CMS","html_regex":["amiro_sys_(css|js).php"],"robots_and":["/admin","/_admin","offset=0","_print_version"]},"ekmps":{"name":"ekmPowershop","html_regex":["/ekmps/(scripts|css|assets|images|shops|designs)","globalstats.ekmsecure.com/hits/stats(-global).js"],"headers_regex":["Set-Cookie: (ekmMsg|ekmpowershop)"]},"godaddywb":{"name":"GoDaddy Website Builder","html_regex":["sf_(wrapper|footer|banner|subnavigation|pagetitle)"],"robots_and":["Disallow: /_backup/","Disallow: /_mygallery/","Disallow: /_temp/","Disallow: /_tempalbums/","Disallow: /_tmpfileop/","Disallow: /dbboon/"]},"wix":{"name":"WIX Website Builder","headers":["X-Wix-"]},"umi":{"name":"UMI.CMS","headers":["X-Generated-By: UMI.CMS"],"robots":["Disallow: /adminzone/"]},"sulu":{"name":"SULU","headers":["x-generator: Sulu"]},"subcms":{"name":"Subrion CMS","headers":["X-Powered-CMS: Subrion CMS"]},"roadz":{"name":"Roadiz CMS","headers":["X-Powered-By: Roadiz CMS"]},"kbcms":{"name":"Kooboo CMS","headers":["X-KoobooCMS-Version"]},"grav":{"name":"GravCMS","headers":["Set-Cookie: grav-site-"]},"exen":{"name":"ExpressionEngine","headers":["Set-Cookie: exp_tracker","Set-Cookie: exp_last_activity","Set-Cookie: exp_last_visit","Set-Cookie: exp_csrf_token="]},"dncms":{"name":"Danneo CMS","headers":["X-Powered-By: CMS Danneo"]},"craft":{"name":"Craft CMS","headers":["X-Powered-By: Craft CMS","Set-Cookie: CraftSessionId"],"robots":["Disallow: /craft/"]},"dragon":{"name":"CPG Dragonfly","headers":["X-Powered-By: Dragonfly CMS"]},"yazd":{"name":"Yazd","headers":["Set-Cookie: yazdLastVisited="]},"oracle_atg":{"name":"Oracle ATG Web Commerce","headers":["X-ATG-Version"]},"coms":{"name":"Commerce Server","headers":["COMMERCE-SERVER-SOFTWARE:","commerce-server-software:"]},"presta":{"name":"PrestaShop","headers":["Powered-By: PrestaShop","Set-Cookie: PrestaShop"],"robots":["robots.txt automaticaly generated by PrestaShop"]},"solusquare":{"name":"Solusquare Commerce Cloud","headers":["Set-Cookie: _SOLUSQUARE"],"robots":["gestion_e_commerce"]},"notion":{"name":"Notion","headers_and":["Set-Cookie","domain=.notion.site"]},"pwind":{"name":"phpWind","headers_regex":["Set-Cookie: [a-zA-Z0-9]{5}_(lastpos|lastvisit)="]},"epis":{"name":"EPiServer","headers_regex":["X-XRDS-Location: (.*?)EPiServerCommunity"]},"lepton":{"name":"LEPTON CMS","headers_regex":["lep(.*?)sessionid"]},"tpc":{"name":"Textpattern CMS","robots":["Disallow: /textpattern"]},"cockpit_cms":{"name":"Cockpit CMS","html":["riot-view","uk-app-page-login","<span>Cockpit</span>","App.request(","view/script"],"path_hint":"/auth/login, /auth/check, /auth/forgotpassword, /storage/tmp/"},"strapi_manual":{"name":"Strapi (headless)","html":["Strapi","/admin/strapi"],"headers":["X-Powered-By: Strapi"]},"directus_manual":{"name":"Directus (headless)","html":["Directus","/admin/login"],"cookies":["directus_session"]},"processwire_manual":{"name":"ProcessWire","html":["ProcessWire","/site/templates/"],"cookies":["wires"],"robots":["/site/templates/"]},"couchcms_manual":{"name":"CouchCMS","html":["CouchCMS"]}}
DBEOF

# ── matching engine ───────────────────────────────────────────────────────────

MATCH_PID_LOG="$TMPDIR/match.log"
RESULTS_JSON="$TMPDIR/results.json"

( python3 - "$BODY_FILE" "$HEADERS_FILE" "$ROBOTS_FILE" "$TMPDIR/signatures.json" "$RESULTS_JSON" << 'PYEOF'
import json, re, sys

body_file, headers_file, robots_file, db_file, out_file = sys.argv[1:6]

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
WEIGHT_AND_GROUP = 22     # AND-groups are stronger signals (multiple conditions confirmed)
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

    for pat in sig.get("html", []):
        if pat.lower() in body.lower():
            score += WEIGHT_LITERAL
            matched.append(f'html: "{pat}"')

    for pat in sig.get("html_regex", []):
        if safe_search(pat, body):
            score += WEIGHT_REGEX
            matched.append(f'html (regex): "{pat}"')

    if sig.get("html_and"):
        and_pats = sig["html_and"]
        if all(p.lower() in body.lower() for p in and_pats):
            score += WEIGHT_AND_GROUP
            matched.append(f'html (all of): {and_pats}')

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
            "path_hint": sig.get("path_hint", "")
        })

# sort descending by confidence score (highest first)
results.sort(key=lambda r: -r["score"])

with open(out_file, "w") as f:
    json.dump(results, f)
PYEOF
) > "$MATCH_PID_LOG" 2>&1 &
MATCH_PID=$!
spinner "$MATCH_PID" "Step 2/2: Matching against signature database (172 CMS)"
wait "$MATCH_PID"

# ── results ───────────────────────────────────────────────────────────────────

echo
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                       RESULTS                         ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo

python3 - "$RESULTS_JSON" << 'PYEOF'
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

# already sorted descending by score from the matching engine, but enforce it
# again here too in case this block is ever reused standalone.
results.sort(key=lambda r: -r["score"])

for r in results:
    c = color_for(r["score"])
    # CMS name always shown in green/bold so it's immediately scannable
    print(f"{BOLD}{GREEN}{r['name']}{NC}")
    print(f"  Confidence: {c}{r['score']:>3}/100{NC}  [{c}{bar(r['score'])}{NC}]")
    for m in r["matched"]:
        print(f"    {CYAN}-{NC} {m}")
    if r.get("path_hint"):
        print(f"    {CYAN}hint paths:{NC} {r['path_hint']}")
    print()
PYEOF

echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "[!] Score is heuristic, not proof - confirm manually before reporting."
echo -e "[!] Unknown CMS? Add a signature block to the DB section of this script."
