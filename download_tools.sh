#!/usr/bin/env bash
# download_tools.sh — Download offensive tools naar http/tools/
# Haalt tools op van officiële GitHub releases en repositories.
# Draai na: git clone → ./install.sh → ./download_tools.sh
#
# Vereist: curl, unzip
# Optioneel: wget (fallback)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/http/tools"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# SharpCollection base URL (Flangvik nightly builds)
SC="https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any"

# Kleuren
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ok=0
fail=0
skip=0

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; ok=$((ok + 1)); }
log_fail() { echo -e "${RED}[-]${NC} $1"; fail=$((fail + 1)); }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; skip=$((skip + 1)); }
log_info() { echo -e "${BLUE}[*]${NC} $1"; }

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
dl() {
    local url="$1" dest="$2"
    if curl -fsSL --connect-timeout 10 --max-time 120 -o "$dest" "$url" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Download single file naar TOOLS_DIR
download_file() {
    local url="$1"
    local filename="${2:-$(basename "$url")}"
    local dest="$TOOLS_DIR/$filename"
    if [ -f "$dest" ]; then
        log_ok "$filename (al aanwezig)"
        return 0
    fi
    if dl "$url" "$dest"; then
        log_ok "$filename"
    else
        log_fail "$filename — download mislukt: $url"
    fi
}

# Download zip, extract specifiek bestand
download_zip_extract() {
    local url="$1"
    local zip_file="$TMP_DIR/$(basename "$url")"
    local extract_pattern="$2"
    local dest_filename="$3"
    local dest="$TOOLS_DIR/$dest_filename"
    if [ -f "$dest" ]; then
        log_ok "$dest_filename (al aanwezig)"
        return 0
    fi
    if dl "$url" "$zip_file"; then
        local extracted
        extracted=$(unzip -jo "$zip_file" "$extract_pattern" -d "$TMP_DIR" 2>/dev/null | grep -c "inflating" || true)
        if [ "$extracted" -gt 0 ] || [ -f "$TMP_DIR/$dest_filename" ]; then
            # Zoek het geëxtraheerde bestand (kan in subdir staan)
            local found
            found=$(find "$TMP_DIR" -name "$dest_filename" -type f 2>/dev/null | head -1)
            if [ -n "$found" ]; then
                mv "$found" "$dest"
                log_ok "$dest_filename (uit zip)"
                return 0
            fi
        fi
        log_fail "$dest_filename — extractie mislukt uit $(basename "$url")"
    else
        log_fail "$dest_filename — zip download mislukt: $url"
    fi
}

# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   Incompetent Bastard — Tool Downloader      ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

mkdir -p "$TOOLS_DIR"

# ===== 1. GITHUB RELEASES (directe downloads) =============================
log_info "=== GitHub Releases ==="

# mimikatz (zip → extract x64/)
if [ -f "$TOOLS_DIR/mimikatz.exe" ] && [ -f "$TOOLS_DIR/mimidrv.sys" ]; then
    log_ok "mimikatz.exe + mimidrv.sys (al aanwezig)"
else
    log_info "Downloaden: mimikatz..."
    if dl "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" "$TMP_DIR/mimikatz.zip"; then
        unzip -jo "$TMP_DIR/mimikatz.zip" "x64/mimikatz.exe" "x64/mimidrv.sys" -d "$TOOLS_DIR" 2>/dev/null
        [ -f "$TOOLS_DIR/mimikatz.exe" ] && log_ok "mimikatz.exe" || log_fail "mimikatz.exe"
        [ -f "$TOOLS_DIR/mimidrv.sys" ] && log_ok "mimidrv.sys" || log_fail "mimidrv.sys"
        # mimi dir (voor scripts die 'mimi' verwachten)
        cp "$TOOLS_DIR/mimikatz.exe" "$TOOLS_DIR/mimi" 2>/dev/null && log_ok "mimi (alias)" || true
    else
        log_fail "mimikatz — download mislukt"
    fi
fi

# PEASS-ng
download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat"
download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"

# winPEASx64_ofs (obfuscated) — als beschikbaar in release
download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe"

# LaZagne
download_file "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe" "lazagne.exe"

# PrintSpoofer
download_file "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe"
download_file "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"

# PrivescCheck
download_file "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"

# PsExec64 (Sysinternals — zip)
download_zip_extract "https://download.sysinternals.com/files/PSTools.zip" "PsExec64.exe" "PsExec64.exe"

# PwnKit (Linux LPE)
download_file "https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit"

# nmap (static Linux binary)
download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap" "nmap"

# nmap Windows installer
download_file "https://nmap.org/dist/nmap-7.94-setup.exe"

# socat (static Linux binary)
download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat"

# plink (PuTTY SSH tunneling)
download_file "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe"

# Chisel (tunneling — Windows + Linux)
if [ ! -f "$TOOLS_DIR/chisel.exe" ]; then
    CHISEL_VER=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/jpillora/chisel/releases/latest" 2>/dev/null | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/') || true
    if [ -n "$CHISEL_VER" ]; then
        if dl "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_amd64.gz" "$TMP_DIR/chisel.exe.gz"; then
            gunzip -f "$TMP_DIR/chisel.exe.gz" && mv "$TMP_DIR/chisel.exe" "$TOOLS_DIR/chisel.exe"
            log_ok "chisel.exe (v${CHISEL_VER})"
        else
            log_fail "chisel.exe"
        fi
    else
        log_fail "chisel.exe — kon versie niet ophalen"
    fi
else
    log_ok "chisel.exe (al aanwezig)"
fi
if [ ! -f "$TOOLS_DIR/chisel" ]; then
    CHISEL_VER=${CHISEL_VER:-$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/jpillora/chisel/releases/latest" 2>/dev/null | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/' || true)}
    if [ -n "$CHISEL_VER" ]; then
        if dl "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_linux_amd64.gz" "$TMP_DIR/chisel.gz"; then
            gunzip -f "$TMP_DIR/chisel.gz" && mv "$TMP_DIR/chisel" "$TOOLS_DIR/chisel"
            log_ok "chisel (Linux, v${CHISEL_VER})"
        else
            log_fail "chisel (Linux)"
        fi
    else
        log_fail "chisel (Linux) — kon versie niet ophalen"
    fi
else
    log_ok "chisel (Linux, al aanwezig)"
fi

# GodPotato
if [ ! -f "$TOOLS_DIR/GodPotato.exe" ]; then
    GODP_URL=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/BeichenDream/GodPotato/releases/latest" 2>/dev/null | grep '"browser_download_url".*GodPotato-NET4.exe' | head -1 | sed 's/.*"\(https[^"]*\)".*/\1/') || true
    if [ -n "$GODP_URL" ]; then
        dl "$GODP_URL" "$TOOLS_DIR/GodPotato.exe" && log_ok "GodPotato.exe" || log_fail "GodPotato.exe"
    else
        log_fail "GodPotato.exe — kon release niet vinden"
    fi
else
    log_ok "GodPotato.exe (al aanwezig)"
fi

# Kerbrute (Linux)
if [ ! -f "$TOOLS_DIR/kerbrute" ]; then
    KERB_URL=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/ropnop/kerbrute/releases/latest" 2>/dev/null | grep '"browser_download_url".*linux_amd64' | head -1 | sed 's/.*"\(https[^"]*\)".*/\1/') || true
    if [ -n "$KERB_URL" ]; then
        dl "$KERB_URL" "$TOOLS_DIR/kerbrute" && log_ok "kerbrute" || log_fail "kerbrute"
    else
        log_fail "kerbrute — kon release niet vinden"
    fi
else
    log_ok "kerbrute (al aanwezig)"
fi

# ===== 2. SHARPCOLLECTION (pre-compiled .NET) ==============================
log_info "=== SharpCollection (Flangvik) ==="

download_file "$SC/Rubeus.exe"
download_file "$SC/Certify.exe"
download_file "$SC/SafetyKatz.exe"
download_file "$SC/SharpKatz.exe"
download_file "$SC/SharpWMI.exe"
download_file "$SC/Whisker.exe"
download_file "$SC/SharpHound.exe"
download_file "$SC/Seatbelt.exe"
download_file "$SC/GoldenGMSA.exe"

# Aanvullende SharpCollection tools (gerefereerd in command files)
download_file "$SC/BetterSafetyKatz.exe"
download_file "$SC/ForgeCert.exe"
download_file "$SC/StandIn.exe"
download_file "$SC/SharpDPAPI.exe"
download_file "$SC/SweetPotato.exe"
download_file "$SC/SharpUp.exe"
download_file "$SC/Snaffler.exe"
download_file "$SC/SharpChrome.exe"
download_file "$SC/SharpRDP.exe"
download_file "$SC/ADFSDump.exe"
download_file "$SC/SharpGPOAbuse.exe"

# SharpSQL (SharpSQLPwn in SharpCollection)
if [ ! -f "$TOOLS_DIR/SharpSQL.exe" ]; then
    if dl "$SC/SharpSQLPwn.exe" "$TOOLS_DIR/SharpSQL.exe"; then
        log_ok "SharpSQL.exe (via SharpSQLPwn)"
    else
        log_fail "SharpSQL.exe"
    fi
else
    log_ok "SharpSQL.exe (al aanwezig)"
fi

# MSSQL (SqlClient in SharpCollection)
if [ ! -f "$TOOLS_DIR/MSSQL.exe" ]; then
    if dl "$SC/SqlClient.exe" "$TOOLS_DIR/MSSQL.exe"; then
        log_ok "MSSQL.exe (via SqlClient)"
    else
        log_fail "MSSQL.exe"
    fi
else
    log_ok "MSSQL.exe (al aanwezig)"
fi

# ===== 3. POWERSHELL SCRIPTS (raw GitHub) ==================================
log_info "=== PowerShell scripts ==="

# PowerSploit
download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1"

# PowerSploit full zip
if [ ! -f "$TOOLS_DIR/powersploit.zip" ]; then
    if dl "https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip" "$TOOLS_DIR/powersploit.zip"; then
        log_ok "powersploit.zip"
    else
        log_fail "powersploit.zip"
    fi
else
    log_ok "powersploit.zip (al aanwezig)"
fi

# PowerUpSQL
download_file "https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1" "Powersql.ps1"

# Powermad
download_file "https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1" "powermad.ps1"

# powercat
download_file "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"

# Nishang
download_file "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1"

# DomainPasswordSpray
download_file "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1" "Invoke-DomainPasswordSpray.ps1"

# SharpHound.ps1 (BloodHound collector — ps1 wrapper)
download_file "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"

# dnscat2 PowerShell client (gerefereerd in net_dnscat2_client)
download_file "https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/dnscat2.ps1"

# Invoke-WMIExec (gerefereerd in lateral_wmi)
download_file "https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1"

# Inveigh (PowerShell LLMNR/NBNS spoofer)
download_file "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1"

# ADRecon
download_file "https://raw.githubusercontent.com/adrecon/ADRecon/master/ADRecon.ps1"

# Invoke-Kerberoast
download_file "https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1"

# linux-exploit-suggester
download_file "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"

# Check-Aanbevelingen (eigen scripts — kopieer vanuit boek/ als aanwezig)
if [ ! -f "$TOOLS_DIR/Check-Aanbevelingen-LOLBin.ps1" ] && [ -f "$SCRIPT_DIR/boek/Check-Aanbevelingen-LOLBin.ps1" ]; then
    cp "$SCRIPT_DIR/boek/Check-Aanbevelingen-LOLBin.ps1" "$TOOLS_DIR/"
    log_ok "Check-Aanbevelingen-LOLBin.ps1 (uit boek/)"
fi
if [ ! -f "$TOOLS_DIR/Check-Aanbevelingen.ps1" ] && [ -f "$SCRIPT_DIR/boek/Check-Aanbevelingen.ps1" ]; then
    cp "$SCRIPT_DIR/boek/Check-Aanbevelingen.ps1" "$TOOLS_DIR/"
    log_ok "Check-Aanbevelingen.ps1 (uit boek/)"
fi

# ===== 4. ANDERE REPOS (bestanden direct in repo) ==========================
log_info "=== Overige repos ==="

# netcat
download_file "https://github.com/int0x33/nc.exe/raw/master/nc.exe"

# SpoolFool
download_file "https://github.com/ly4k/SpoolFool/raw/main/SpoolFool.exe"

# RottenPotato
download_file "https://github.com/breenmachine/RottenPotatoNG/raw/master/RottenPotatoEXE/x64/Release/MSFRottenPotato.exe" "rottenpotato.exe"

# PsBypassCLM
download_file "https://github.com/padovah4ck/PSByPassCLM/raw/master/PSBypassCLM/PSBypassCLM/bin/x64/Debug/PsBypassCLM.exe"

# Invisi-Shell (dll + bat)
download_file "https://github.com/OmerYa/Invisi-Shell/raw/master/x64/Release/InvisiShellProfiler.dll" "invisi.dll"
download_file "https://raw.githubusercontent.com/OmerYa/Invisi-Shell/master/RunWithPathAsAdmin.bat"

# PetitPotam (Python)
download_file "https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py"
# Wrapper zodat 'PetitPotam.exe' verwijzing werkt als alias
if [ ! -f "$TOOLS_DIR/PetitPotam.exe" ] && [ -f "$TOOLS_DIR/PetitPotam.py" ]; then
    cp "$TOOLS_DIR/PetitPotam.py" "$TOOLS_DIR/PetitPotam.exe"
    log_ok "PetitPotam.exe (kopie van .py)"
fi

# Invoke-DCSync
download_file "https://raw.githubusercontent.com/pentestfactory/Invoke-DCSync/main/Invoke-DCSync.ps1" "Invoke-DCsync.ps1"

# Coercer (Python — NTLM authentication coercion)
download_file "https://raw.githubusercontent.com/p0dalirius/Coercer/main/coercer/__main__.py" "Coercer.py"

# dementor (Python — printer bug trigger)
download_file "https://raw.githubusercontent.com/NotMedic/NetNTLMtoSilverTicket/master/dementor.py"

# Find-PSRemotingLocalAdminAccess (verwijderd uit nishang, fork)
download_file "https://raw.githubusercontent.com/samratashok/nishang/master/Find/Find-PSRemotingLocalAdminAccess.ps1"

# AmsiTrigger (GitHub release)
if [ ! -f "$TOOLS_DIR/AmsiTrigger_x64.exe" ]; then
    AMSI_URL=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/RythmStick/AMSITrigger/releases/latest" 2>/dev/null | grep '"browser_download_url".*AmsiTrigger_x64.exe' | head -1 | sed 's/.*"\(https[^"]*\)".*/\1/') || true
    if [ -n "$AMSI_URL" ]; then
        dl "$AMSI_URL" "$TOOLS_DIR/AmsiTrigger_x64.exe" && log_ok "AmsiTrigger_x64.exe" || log_fail "AmsiTrigger_x64.exe"
    else
        log_fail "AmsiTrigger_x64.exe — kon release niet vinden"
    fi
else
    log_ok "AmsiTrigger_x64.exe (al aanwezig)"
fi

# ShadowCoerce (Python — NTLM coercion via MS-FSRVP)
download_file "https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/main/shadowcoerce.py"

# pywhisker (Python — Shadow Credentials attack)
download_file "https://raw.githubusercontent.com/ShutdownRepo/pywhisker/main/pywhisker.py"

# noPac (Python — SAMAccountName / CVE-2021-42278+42287)
download_file "https://raw.githubusercontent.com/Ridter/noPac/main/noPac.py"

# PXEThief (Python — SCCM PXE credential extraction)
download_file "https://raw.githubusercontent.com/MWR-CyberSec/PXEThief/main/pxethief.py"

# pygpoabuse (Python — GPO abuse for persistence)
download_file "https://raw.githubusercontent.com/Hackndo/pygpoabuse/main/pygpoabuse.py"

# firefox_decrypt (Python — extract Firefox saved passwords)
download_file "https://raw.githubusercontent.com/unode/firefox_decrypt/main/firefox_decrypt.py"

# KrbRelayUp (GitHub release — local Kerberos relay privesc)
if [ ! -f "$TOOLS_DIR/KrbRelayUp.exe" ]; then
    KRU_URL=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/Dec0ne/KrbRelayUp/releases/latest" 2>/dev/null | grep '"browser_download_url".*KrbRelayUp.exe' | head -1 | sed 's/.*"\(https[^"]*\)".*/\1/') || true
    if [ -n "$KRU_URL" ]; then
        dl "$KRU_URL" "$TOOLS_DIR/KrbRelayUp.exe" && log_ok "KrbRelayUp.exe" || log_fail "KrbRelayUp.exe"
    else
        log_fail "KrbRelayUp.exe — kon release niet vinden"
    fi
else
    log_ok "KrbRelayUp.exe (al aanwezig)"
fi

# ===== 5. TOOLS DIE COMPILATIE VEREISEN / HANDMATIG ========================
log_info "=== Handmatig (compilatie of commercieel) ==="

[ -f "$TOOLS_DIR/PingCastle.exe" ] && log_ok "PingCastle.exe (al aanwezig)" || \
    log_warn "PingCastle.exe — handmatig downloaden: https://www.pingcastle.com/download/"

[ -f "$TOOLS_DIR/SpoolSample.exe" ] && log_ok "SpoolSample.exe (al aanwezig)" || \
    log_warn "SpoolSample.exe — compileer zelf: https://github.com/leechristensen/SpoolSample"

[ -f "$TOOLS_DIR/spool.exe" ] && log_ok "spool.exe (al aanwezig)" || \
    log_warn "spool.exe — compileer zelf of gebruik SpoolSample/PrintSpoofer"

[ -f "$TOOLS_DIR/MS-RPRN.exe" ] && log_ok "MS-RPRN.exe (al aanwezig)" || \
    log_warn "MS-RPRN.exe — compileer zelf: https://github.com/leechristensen/SpoolSample (C++ project)"

[ -f "$TOOLS_DIR/Outflank-Dumpert.exe" ] && log_ok "Outflank-Dumpert.exe (al aanwezig)" || \
    log_warn "Outflank-Dumpert.exe — compileer zelf: https://github.com/outflanknl/Dumpert"

[ -f "$TOOLS_DIR/Loader.exe" ] && log_ok "Loader.exe (al aanwezig)" || \
    log_warn "Loader.exe — compileer zelf: https://github.com/Flangvik/NetLoader"

[ -f "$TOOLS_DIR/SCShell.exe" ] && log_ok "SCShell.exe (al aanwezig)" || \
    log_warn "SCShell.exe — compileer zelf: https://github.com/Mr-Un1k0d3r/SCShell"

[ -f "$TOOLS_DIR/SharpSCCM.exe" ] && log_ok "SharpSCCM.exe (al aanwezig)" || \
    log_warn "SharpSCCM.exe — compileer zelf: https://github.com/Mayyhem/SharpSCCM"

# ===== 6. LOKALE / CUSTOM BESTANDEN =======================================
log_info "=== Lokale bestanden ==="

for custom in admin.bat user.bat yolo.ps1 druva.py; do
    [ -f "$TOOLS_DIR/$custom" ] && log_ok "$custom (lokaal)" || \
        log_warn "$custom — lokaal/custom bestand, niet beschikbaar via download"
done

[ -f "$TOOLS_DIR/netscan.exe" ] && log_ok "netscan.exe (al aanwezig)" || \
    log_warn "netscan.exe — commercieel: https://www.softperfect.com/products/networkscanner/"

# ===== 7. CHMOD voor Linux tools ==========================================
chmod +x "$TOOLS_DIR/linpeas.sh" "$TOOLS_DIR/PwnKit" "$TOOLS_DIR/nmap" \
         "$TOOLS_DIR/socat" "$TOOLS_DIR/chisel" "$TOOLS_DIR/kerbrute" \
         "$TOOLS_DIR/linux-exploit-suggester.sh" 2>/dev/null || true

# ===== SAMENVATTING ========================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Gedownload:${NC}  $ok"
echo -e "  ${RED}Mislukt:${NC}     $fail"
echo -e "  ${YELLOW}Overgeslagen:${NC} $skip"
echo -e "  ${BLUE}Totaal:${NC}      $(ls -1 "$TOOLS_DIR" | wc -l | tr -d ' ') bestanden in http/tools/"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""
if [ "$fail" -gt 0 ]; then
    log_info "Sommige downloads zijn mislukt. Controleer je internetverbinding of download handmatig."
fi
if [ "$skip" -gt 0 ]; then
    log_info "Overgeslagen tools moeten handmatig gecompileerd of gedownload worden."
fi
