#!/bin/bash
set -euo pipefail

JSON="$1"
OUT="$2"
CONF="classifications.conf"

# Check requirements
command -v jq >/dev/null || { echo "jq is vereist"; exit 1; }
[[ -f "$CONF" ]] || { echo "Configuratiebestand ontbreekt"; exit 1; }

# Load classifications
declare -A CLASS
while IFS='=' read -r key val; do
    [[ -z "${key:-}" || "$key" =~ ^# ]] && continue
    CLASS["$key"]="$val"
done < "$CONF"

# Centralized mappings
declare -A PRIORITY=( [GOED]=1 [VOLDOENDE]=2 [UITFASEREN]=3 [ONVOLDOENDE]=4 [ONBEKEND]=9 [n.v.t.]=0 )
declare -A COLOR=( [GOED]="#4CAF50" [VOLDOENDE]="#FFCC80" [UITFASEREN]="#FB8C00" [ONVOLDOENDE]="#F44336" [ONBEKEND]="#9E9E9E" [n.v.t.]="#9E9E9E" )

classify() {
    local key="$1:$2"
    [[ -z "${CLASS[$key]:-}" ]] && echo "ONBEKEND" && echo "UNKNOWN: $key" >&2 || echo "${CLASS[$key]}"
}

prio() {
    echo "${PRIORITY[$1]:-9}"
}

color() {
    echo "${COLOR[$1]:-#9E9E9E}"
}

# HTML header
cat > "$OUT" <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body { font-family: Arial; font-size:12px; }
table { border-collapse: collapse; width: auto; margin-bottom:20px;}
td, th { border:1px solid #ccc; padding:4px; }
.badge { color:#fff; padding:2px 6px; border-radius:4px;}
.finding { color: blue; cursor: pointer; text-decoration: underline; }

.popup {
  display: none;
  position: fixed;
  top: 20%;
  left: 50%;
  transform: translate(-50%, -20%);
  background: white;
  padding: 20px;
  border: 2px solid #444;
  box-shadow: 0 0 10px rgba(0,0,0,0.5);
  z-index: 9999;
}
.popup-close { cursor: pointer; float: right; font-weight: bold; }
</style>
</head>
<body>
<h1>TLS Rapport</h1>

<div id="popup" class="popup">
  <span class="popup-close" onclick="closePopup()">X</span>
  <h3 id="popupTitle"></h3>
  <ul id="hostList"></ul>
</div>

<script>
document.addEventListener("click", function(e) {
  if (e.target.classList.contains("finding")) {
    document.getElementById("popupTitle").textContent = e.target.dataset.title;
    const hosts = e.target.dataset.hosts.split(",");
    const list = document.getElementById("hostList");
    list.innerHTML = "";
    hosts.forEach(h => { const li = document.createElement("li"); li.textContent = h; list.appendChild(li); });
    document.getElementById("popup").style.display = "block";
  }
});
function closePopup() { document.getElementById("popup").style.display = "none"; }
</script>
EOF

# Helper function to generate HTML tables
generate_table() {
    local title="$1"    # e.g., "TLS versies"
    local header="$2"   # e.g., "<th>Versie</th><th>Status</th><th>Classificatie</th>"
    local jq_filter="$3" # jq script that outputs: TSV with fields: <value> <finding> <hosts>...
    local classify_key="$4" # classification key prefix
    local type_col="${5:-}" # optional first column for KEX/EC/SIG
    
    echo "<h2>$title</h2><table>" >> "$OUT"
    echo "<tr>$header</tr>" >> "$OUT"
    
    # Process each line: value/finding/hosts
    jq -r "$jq_filter" "$JSON" | while IFS=$'\t' read -r val finding hosts; do
        [[ -z "$val" ]] && continue
        # Determine level
        if [[ "$title" == "TLS versies" && "${finding,,}" =~ ^not\ offered ]]; then
            level="n.v.t."
        else
            level=$(classify "$classify_key" "$val")
        fi
        p=$(prio "$level")
        c=$(color "$level")
        # Optional type column
        [[ -n "$type_col" ]] && type_html="<td>$type_col</td>" || type_html=""
        if [[ "$title" == "TLS versies" ]]; then
            printf "%s;<tr>%s<td><span class=\"finding\" data-hosts=\"%s\" data-title=\"%s\">%s</span></td><td><span class=\"badge\" style=\"background:%s\">%s</span></td></tr>\n" \
            "$p" "$type_html" "$hosts" "$val: $finding" "$val: $finding" "$c" "$level"
        else
            printf "%s;<tr>%s<td><span class=\"finding\" data-hosts=\"%s\" data-title=\"%s\">%s</span></td><td><span class=\"badge\" style=\"background:%s\">%s</span></td></tr>\n" \
            "$p" "$type_html" "$hosts" "$val" "$val" "$c" "$level"
        fi
    done | sort -t';' -k1,1n | cut -d';' -f2- >> "$OUT"
    
    echo "</table>" >> "$OUT"
}

###############################################
# TLS versies
###############################################
generate_table "TLS versies" "<th>Bevinding</th><th>Classificatie</th>" '
map(select(.id|test("^(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3)$"))) |
group_by([.id, .finding]) |
map({
  id: .[0].id,
  finding: .[0].finding,
  hosts: (map(((.ip | split("/") | .[1]) + ":" + (.port|tostring))) | unique | join(","))
}) |
.[] | [.id, .finding, .hosts] | @tsv
' "TLSVER"

###############################################
# Certificaten - signature algorithms
###############################################
generate_table "Certificaten" "<th>Signature algorithm</th><th>Classificatie</th>" '
map(select(.id|startswith("cert_signatureAlgorithm"))) |
map({
  words: [.finding],
  host: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))
}) |
map(.words[] as $w | {val: $w, finding: $w, hosts: .host}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts) | unique | join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "CSIGALG"

# Certificaten - key size
generate_table "" "<th>Key size</th><th>Classificatie</th>" '
map(select(.id|startswith("cert_keySize"))) |
map({
  words: [.finding],
  host: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))
}) |
map(.words[] as $w | {val: $w, finding: $w, hosts: .host}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts) | unique | join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "CKEYSIZE"

# Ciphers TLS 1.2
generate_table "TLSv1.2 ciphers" "<th>Cipher</th><th>Classificatie</th>" '
map(select(.id|startswith("cipher-tls1_2"))) |
map({val: (.finding | [splits("\\s+")][-1]), finding: .finding, hosts: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts)|unique|join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "CIPHER12"

# Ciphers TLS 1.3
generate_table "TLSv1.3 ciphers" "<th>Cipher</th><th>Classificatie</th>" '
map(select(.id|startswith("cipher-tls1_3"))) |
map({val: (.finding | [splits("\\s+")][-1]), finding: .finding, hosts: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts)|unique|join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "CIPHER13"

# KEX / DH groups
generate_table "Diffie Hellman" "<th>Type</th><th>Naam</th><th>Classificatie</th>" '
map(select(.id=="DH_groups")) |
map({
  words: (if (.finding|startswith("RFC")) then [.finding] else (.finding|split(" ")|unique|sort) end),
  host: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))
}) |
map(.words[] as $w | {val: $w, finding: $w, hosts: .host}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts)|unique|join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "KEX" "Finite field group"

# Elliptic curves
generate_table "Elliptic Curves" "<th>Type</th><th>Naam</th><th>Classificatie</th>" '
map(select(.id|test("^(FS_ECDHE_curves|FS_KEMs)$"))) |
map({
  words: (if (.finding|startswith("RFC")) or (.finding|startswith("No KEMs offered")) then [.finding] else (.finding|split(" ")|unique|sort) end),
  host: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))
}) |
map(.words[] as $w | {val: $w, finding: $w, hosts: .host}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts)|unique|join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "ECKEX" "Elliptic curve"

# Signature algorithms
generate_table "Signature algorithms" "<th>Type</th><th>Naam</th><th>Classificatie</th>" '
map(select(.id|test("^(FS_TLS12_sig_algs|FS_TLS13_sig_algs)$"))) |
map({
  words: (.finding|split(" ")|unique|sort),
  host: ((.ip | split("/") | .[1]) + ":" + (.port|tostring))
}) |
map(.words[] as $w | {val: $w, finding: $w, hosts: .host}) |
group_by(.val) |
map({val: .[0].val, finding: .[0].finding, hosts: (map(.hosts)|unique|join(","))}) |
.[] | [.val, .finding, .hosts] | @tsv
' "SIG" "Algorithm"

# HTML footer
echo "</body></html>" >> "$OUT"
