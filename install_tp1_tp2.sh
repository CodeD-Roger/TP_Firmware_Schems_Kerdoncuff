#!/bin/bash
# ============================================================
#  TP Firmware — TP1 Analyse Statique + TP2 Reverse Engineering
#  Cours Cybersécurité IoT — Jour 2
# ============================================================

set +e

BOLD="\033[1m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

# Fonctionne que lancé en sudo, sudo su, ou user normal
if [[ $EUID -eq 0 && -n "$SUDO_USER" ]]; then
  REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  REAL_HOME="$HOME"
fi

BASE="$REAL_HOME/IoT/formation-Jour2/firmware-analysis"
# Si lancé en sudo su direct, HOME=/root — on force /root
[[ $EUID -eq 0 && -z "$SUDO_USER" ]] && BASE="/root/IoT/formation-Jour2/firmware-analysis"

FIRMWARE="$BASE/firmware.bin"

banner() {
  echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
  echo -e "${CYAN}${BOLD}  $1${RESET}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}\n"
}
ok()    { echo -e "  ${GREEN}✔  $1${RESET}"; }
info()  { echo -e "  ${YELLOW}▸  $1${RESET}"; }
fail()  { echo -e "  ${RED}✘  $1 — arrêt${RESET}"; exit 1; }
title() { echo -e "\n  ${BOLD}$1${RESET}"; }

# ────────────────────────────────────────────────────────────
banner "Préparation de l'environnement"

mkdir -p "$BASE"
cd "$BASE" || fail "Impossible d'accéder à $BASE"
ok "Dossier de travail : $BASE"

# ────────────────────────────────────────────────────────────
banner "TP1 — Installation des outils"

info "Mise à jour des paquets..."
apt-get update -qq

for tool in binwalk curl wget file binutils; do
  dpkg -l "$tool" &>/dev/null 2>&1 \
    && ok "$tool déjà installé" \
    || { apt-get install -y -qq "$tool" && ok "$tool installé" || info "$tool non disponible"; }
done

python3 -c "import lzma" 2>/dev/null \
  && ok "python3-lzma disponible" \
  || { apt-get install -y -qq python3-lzma 2>/dev/null; ok "python3-lzma installé"; }

pip3 install jefferson 2>/dev/null | tail -1 && ok "jefferson (JFFS2) installé"

# ────────────────────────────────────────────────────────────
banner "TP1 — Vérification du firmware"

# Vérifie que le firmware est valide (pas une page HTML, taille > 100Ko)
is_valid_firmware() {
  local f="$1"
  [[ ! -f "$f" ]] && return 1
  local size
  size=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [[ "$size" -lt 102400 ]] && return 1          # < 100Ko = suspect
  file "$f" | grep -qiE "HTML|text" && return 1 # page d'erreur
  return 0
}

if is_valid_firmware "$FIRMWARE"; then
  SIZE=$(du -h "$FIRMWARE" | cut -f1)
  ok "Firmware valide déjà présent : $FIRMWARE ($SIZE)"
  file "$FIRMWARE"
else
  info "Firmware absent ou invalide — téléchargement..."
  FIRMWARE_URL="https://hosting.pilsfree.net/morce/Firmware/OpenWRT/openwrt-ar71xx-generic-tl-wr841n-v8-squashfs-factory.bin"
  wget -q --show-progress -O "$FIRMWARE" "$FIRMWARE_URL" 2>&1 \
    || curl -L --progress-bar -o "$FIRMWARE" "$FIRMWARE_URL" 2>&1

  if is_valid_firmware "$FIRMWARE"; then
    ok "Firmware téléchargé : $(du -h $FIRMWARE | cut -f1)"
  else
    fail "Firmware invalide après téléchargement — place firmware.bin manuellement dans $BASE"
  fi
fi

# ────────────────────────────────────────────────────────────
banner "TP1 — Analyse Binwalk"

title "Étape 3 : Analyse des signatures"
echo ""
binwalk "$FIRMWARE" | tee "$BASE/binwalk_analyse.txt"
ok "Résultats → binwalk_analyse.txt"

title "Étape 4 : Extraction récursive (peut prendre 1-2 min)"
EXTRACTED_DIR="$BASE/_firmware.bin.extracted"
rm -rf "$EXTRACTED_DIR"
binwalk -Me --run-as=root "$FIRMWARE" 2>&1 | tee "$BASE/binwalk_extraction.log"
ok "Extraction terminée"

# ────────────────────────────────────────────────────────────
banner "TP1 — Exploration du filesystem"

# Cherche squashfs-root à n'importe quelle profondeur
EXTRACTED=$(find "$BASE" -name "squashfs-root" -type d 2>/dev/null | head -1)

if [[ -n "$EXTRACTED" ]]; then
  ok "Filesystem trouvé : $EXTRACTED"
  NB=$(find "$EXTRACTED" -type f 2>/dev/null | wc -l)
  ok "$NB fichiers dans le filesystem"

  title "Étape 5 : Binaires ELF"
  find "$EXTRACTED" -type f -exec file {} \; 2>/dev/null \
    | grep ELF \
    | tee "$BASE/elf_files.txt"
  NB_ELF=$(wc -l < "$BASE/elf_files.txt")
  ok "$NB_ELF binaires ELF → elf_files.txt"

  title "Étape 6 : Fichiers critiques"

  echo -e "\n  ${BOLD}→ /etc/passwd :${RESET}"
  [[ -f "$EXTRACTED/etc/passwd" ]] \
    && cat "$EXTRACTED/etc/passwd" | head -20 \
    || info "Absent"

  echo -e "\n  ${BOLD}→ /etc/shadow :${RESET}"
  [[ -f "$EXTRACTED/etc/shadow" ]] \
    && cat "$EXTRACTED/etc/shadow" | head -20 \
    || info "Absent"

  echo -e "\n  ${BOLD}→ Scripts init.d :${RESET}"
  [[ -d "$EXTRACTED/etc/init.d" ]] \
    && ls "$EXTRACTED/etc/init.d/" \
    || info "Absent"

  echo -e "\n  ${BOLD}→ Interface web /www/ :${RESET}"
  [[ -d "$EXTRACTED/www" ]] \
    && ls "$EXTRACTED/www/" \
    || info "Absent"

else
  info "squashfs-root non trouvé — listing de l'extraction :"
  find "$EXTRACTED_DIR" -maxdepth 3 -type d 2>/dev/null | head -20
  info "Binwalk a peut-être utilisé un autre nom — recherche..."
  ROOTFS=$(find "$BASE" -maxdepth 6 \( -name "rootfs" -o -name "root" -o -name "squashfs*" \) -type d 2>/dev/null | head -1)
  if [[ -n "$ROOTFS" ]]; then
    ok "Filesystem alternatif trouvé : $ROOTFS"
    EXTRACTED="$ROOTFS"
    find "$EXTRACTED" -type f -exec file {} \; 2>/dev/null | grep ELF | tee "$BASE/elf_files.txt"
  fi
fi

# Sauvegarde l'architecture
if [[ -n "$EXTRACTED" ]]; then
  find "$EXTRACTED" -type f -exec file {} \; 2>/dev/null \
    | grep ELF | head -5 \
    | tee "$BASE/architecture.txt"
fi

# ────────────────────────────────────────────────────────────
banner "TP2 — Installation Radare2"

if command -v r2 &>/dev/null; then
  ok "Radare2 déjà installé : $(r2 -v 2>/dev/null | head -1)"
else
  apt-get install -y -qq radare2 2>/dev/null \
    && ok "Radare2 installé" \
    || info "Radare2 non disponible via apt"
fi

# ────────────────────────────────────────────────────────────
banner "TP2 — Reverse Engineering"

# Cherche la meilleure cible
TARGET=""
for candidate in httpd lighttpd uhttpd busybox telnetd udhcpd dropbear; do
  found=$(find "$BASE" -name "$candidate" -type f 2>/dev/null | head -1)
  if [[ -n "$found" ]]; then
    TARGET="$found"
    ok "Cible : $candidate → $TARGET"
    break
  fi
done

# Fallback : premier ELF trouvé
if [[ -z "$TARGET" ]]; then
  TARGET=$(find "$BASE" -type f -exec file {} \; 2>/dev/null \
    | grep "ELF" | grep -v "\.extracted" | head -1 | cut -d: -f1)
  [[ -n "$TARGET" ]] && info "Cible par défaut : $TARGET"
fi

if [[ -n "$TARGET" ]]; then
  BIN="$(basename $TARGET)"

  title "Architecture et type"
  file "$TARGET"
  readelf -h "$TARGET" 2>/dev/null | grep -E "Machine|Class|Endian"

  title "Passwords potentiels"
  strings "$TARGET" | grep -iE "password|passwd|secret|credential" \
    | head -20 | tee "$BASE/${BIN}_passwords.txt"

  title "Comptes admin"
  strings "$TARGET" | grep -iE "admin|root|login|user" \
    | head -20 | tee "$BASE/${BIN}_admin.txt"

  title "Appels shell dangereux"
  strings "$TARGET" | grep -E "/bin/sh|/bin/bash|system\(|execve|popen" \
    | head -20 | tee "$BASE/${BIN}_shell.txt"

  title "Références /etc/"
  strings "$TARGET" | grep '/etc/' \
    | head -20 | tee "$BASE/${BIN}_etc.txt"

  title "Chargement dynamique"
  strings "$TARGET" | grep -iE "dlopen|dlsym" | head -10

  title "Réseau / firewall"
  strings "$TARGET" | grep -iE "ipsec|firewall|qos|traffic|iptables" | head -10

  title "Fonctions dangereuses"
  strings "$TARGET" | grep -E "strcpy|strcat|sprintf|gets$" | head -10

  ok "Résultats strings sauvegardés dans $BASE/"

  if command -v r2 &>/dev/null; then
    title "Radare2 — liste des fonctions"
    timeout 60 r2 -A -q -c 'afl' "$TARGET" 2>/dev/null \
      | head -30 \
      | tee "$BASE/${BIN}_r2_functions.txt" \
      && ok "Fonctions → ${BIN}_r2_functions.txt" \
      || info "Timeout r2 — lance manuellement : r2 $TARGET"
  fi

  # Backup passwd si trouvé
  [[ -n "$EXTRACTED" && -f "$EXTRACTED/etc/passwd" ]] && {
    cp "$EXTRACTED/etc/passwd" "$BASE/passwd.backup"
    ok "passwd.backup créé"
  }

else
  info "Aucun binaire ELF trouvé — extraction incomplète ?"
fi

# ────────────────────────────────────────────────────────────
banner "Récapitulatif TP1 + TP2"

echo -e "  ${BOLD}Dossier : $BASE${RESET}"
echo ""
echo "  Fichiers produits :"
ls "$BASE"/*.txt "$BASE"/*.log "$BASE/passwd.backup" 2>/dev/null \
  | while read f; do echo "  ├── $(basename $f)"; done
echo ""
[[ -n "$EXTRACTED" ]] && echo -e "  Filesystem : $EXTRACTED"
[[ -n "$TARGET" ]]    && echo -e "  Cible analysée : $TARGET"
echo ""
echo -e "  ${GREEN}${BOLD}✔  TP1 + TP2 terminés !${RESET}"
echo ""
