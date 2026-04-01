#!/bin/bash
# ============================================================
#  TP Firmware — TP3 Émulation + TP4 Analyse Dynamique + TP5 Patching
#  Cours Cybersécurité IoT — Jour 2
# ============================================================

set +e

BOLD="\033[1m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

BASE=~/IoT/formation-Jour2/firmware-analysis

banner() {
  echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
  echo -e "${CYAN}${BOLD}  $1${RESET}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}\n"
}
ok()    { echo -e "  ${GREEN}✔  $1${RESET}"; }
info()  { echo -e "  ${YELLOW}▸  $1${RESET}"; }
warn()  { echo -e "  ${YELLOW}⚠  $1${RESET}"; }
fail()  { echo -e "  ${RED}✘  $1${RESET}"; }
title() { echo -e "\n  ${BOLD}$1${RESET}"; }

# ────────────────────────────────────────────────────────────
banner "Vérification des prérequis"

[[ -d "$BASE" ]] && ok "Dossier de travail trouvé : $BASE" \
  || { fail "Dossier $BASE introuvable — lance d'abord install_tp1_tp2.sh"; exit 1; }

cd "$BASE" || exit 1

FIRMWARE=$(find "$BASE" -name "firmware.bin" 2>/dev/null | head -1)
[[ -n "$FIRMWARE" ]] && ok "Firmware trouvé : $FIRMWARE" \
  || { fail "firmware.bin introuvable — lance d'abord install_tp1_tp2.sh"; exit 1; }

EXTRACTED=$(find "$BASE" -name "squashfs-root" -type d 2>/dev/null | head -1)
[[ -n "$EXTRACTED" ]] && ok "Filesystem extrait : $EXTRACTED" \
  || warn "squashfs-root non trouvé — certaines étapes TP5 seront limitées"

# ────────────────────────────────────────────────────────────
banner "TP3 — Installation QEMU + Firmadyne"

info "Installation QEMU (émulation MIPS/ARM)..."
apt-get update -qq
QEMU_PKGS=(qemu-system-mips qemu-system-arm qemu-utils qemu-user-static)
for pkg in "${QEMU_PKGS[@]}"; do
  apt-get install -y -qq "$pkg" 2>/dev/null && ok "$pkg installé" || warn "$pkg non disponible"
done

# Dépendances Firmadyne
info "Installation des dépendances Firmadyne..."
DEPS=(git python3 python3-pip busybox-static fakeroot kpartx snmp uml-utilities \
      util-linux vlan bridge-utils wget curl netcat-openbsd nmap)
for dep in "${DEPS[@]}"; do
  apt-get install -y -qq "$dep" 2>/dev/null && ok "$dep" || warn "$dep non disponible"
done

# PostgreSQL pour Firmadyne
info "Installation PostgreSQL (base Firmadyne)..."
apt-get install -y -qq postgresql postgresql-client 2>/dev/null \
  && ok "PostgreSQL installé" || warn "PostgreSQL non disponible"

# ────────────────────────────────────────────────────────────
banner "TP3 — Clonage et configuration de Firmadyne"

FIRMADYNE_DIR="$BASE/firmadyne"

if [[ -d "$FIRMADYNE_DIR/.git" ]]; then
  ok "Firmadyne déjà cloné — mise à jour..."
  cd "$FIRMADYNE_DIR" && git pull -q 2>/dev/null && ok "Mis à jour"
else
  info "Clonage de Firmadyne..."
  git clone --depth=1 https://github.com/firmadyne/firmadyne.git "$FIRMADYNE_DIR" 2>&1 \
    && ok "Firmadyne cloné dans $FIRMADYNE_DIR" \
    || { fail "Impossible de cloner Firmadyne — vérifier la connexion internet"; }
fi

cd "$FIRMADYNE_DIR" || exit 1

# Sous-modules (binaires QEMU pré-compilés pour MIPS/ARM)
info "Chargement des sous-modules (noyaux MIPS/ARM)..."
git submodule update --init --recursive 2>&1 | tail -3
ok "Sous-modules chargés"

# Installation des dépendances Python
[[ -f "requirements.txt" ]] && {
  info "Installation des dépendances Python..."
  pip3 install -r requirements.txt -q 2>/dev/null && ok "Dépendances Python installées"
}

# Configuration firmadyne.config
if [[ -f "firmadyne.config" ]]; then
  # Mise à jour du chemin
  sed -i "s|FIRMWARE_DIR=.*|FIRMWARE_DIR=$FIRMADYNE_DIR|" firmadyne.config
  ok "firmadyne.config mis à jour"
else
  cat > firmadyne.config << EOF
FIRMWARE_DIR=$FIRMADYNE_DIR
PSQL_IP=127.0.0.1
PSQL_PORT=5432
PSQL_DB=firmware
PSQL_USER=firmadyne
PSQL_PASS=firmadyne
EOF
  ok "firmadyne.config créé"
fi

# Initialisation PostgreSQL
info "Configuration de la base PostgreSQL..."
service postgresql start 2>/dev/null || true
sleep 2
sudo -u postgres psql -c "CREATE USER firmadyne WITH PASSWORD 'firmadyne';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE firmware OWNER firmadyne;" 2>/dev/null || true
[[ -f "database/schema" ]] && sudo -u postgres psql -U firmadyne -d firmware < database/schema 2>/dev/null || true
ok "Base de données configurée"

# ────────────────────────────────────────────────────────────
banner "TP3 — Émulation du firmware"

cd "$FIRMADYNE_DIR"

title "Étape 2 : Import du firmware dans Firmadyne"
cp "$FIRMWARE" "$FIRMADYNE_DIR/firmware.bin" 2>/dev/null

if [[ -f "scripts/extractor.py" ]]; then
  info "Extraction Firmadyne..."
  python3 scripts/extractor.py -b TP_FIRMWARE -sql 127.0.0.1 -np -nk \
    "$FIRMADYNE_DIR/firmware.bin" "$FIRMADYNE_DIR/images" 2>&1 | tail -5
  ok "Firmware importé"
elif [[ -f "scripts/extract.sh" ]]; then
  bash scripts/extract.sh "$FIRMADYNE_DIR/firmware.bin" 2>&1 | tail -5
  ok "Firmware extrait"
else
  warn "Script d'extraction non trouvé — vérifier l'installation Firmadyne"
fi

title "Étape 3 : Détection de l'architecture"
if [[ -f "scripts/getArch.sh" ]]; then
  bash scripts/getArch.sh 2>&1 | tee "$BASE/architecture.txt"
  ok "Architecture détectée → architecture.txt"
else
  # Détection manuelle via le filesystem extrait
  if [[ -n "$EXTRACTED" ]]; then
    ARCH_INFO=$(find "$EXTRACTED" -type f -exec file {} \; 2>/dev/null | grep ELF | head -3)
    echo "$ARCH_INFO" | tee "$BASE/architecture.txt"
    ok "Architecture détectée manuellement → architecture.txt"
  fi
fi

title "Étape 4 : Lancement de l'émulation"
info "Tentative de démarrage QEMU..."

if [[ -f "scratch/1/run.sh" ]]; then
  info "Script run.sh trouvé — lancement en arrière-plan (30s timeout pour démarrage)..."
  bash scratch/1/run.sh &
  QEMU_PID=$!
  sleep 30
  if kill -0 $QEMU_PID 2>/dev/null; then
    ok "QEMU en cours d'exécution (PID: $QEMU_PID)"
    echo "$QEMU_PID" > "$BASE/qemu.pid"
  else
    warn "QEMU s'est arrêté — vérifier les logs"
  fi
elif [[ -f "scripts/run.sh" ]]; then
  info "Lancement via scripts/run.sh..."
  bash scripts/run.sh 2>&1 | tee "$BASE/qemu_boot.log" &
  sleep 20
  ok "Émulation lancée — voir $BASE/qemu_boot.log"
else
  warn "Script run.sh non trouvé"
  info "Lancement QEMU manuel pour MIPS (exemple) :"
  echo ""
  echo "  qemu-system-mips -M malta -kernel vmlinux \\"
  echo "    -drive if=ide,format=raw,file=image.raw \\"
  echo "    -append 'root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64' \\"
  echo "    -net nic -net tap,ifname=tap0,script=no \\"
  echo "    -nographic"
fi

# Détection de l'IP émulée
title "Étape 5 : Détection de l'IP émulée"
sleep 5
EMULATED_IP=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$BASE/qemu_boot.log" 2>/dev/null | \
  grep -v "^127\.\|^0\." | head -1)
if [[ -n "$EMULATED_IP" ]]; then
  ok "IP émulée détectée : $EMULATED_IP"
  echo "$EMULATED_IP" > "$BASE/emulated_ip.txt"
else
  warn "IP émulée non détectée automatiquement"
  info "Après démarrage, vérifier avec : cat $BASE/qemu_boot.log | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}'"
  EMULATED_IP="192.168.0.1"
  info "IP supposée pour la suite : $EMULATED_IP"
fi

# ────────────────────────────────────────────────────────────
banner "TP4 — Analyse dynamique"

title "Étape 1 : Scan des ports (nmap)"
echo ""
if command -v nmap &>/dev/null; then
  info "Scan nmap de $EMULATED_IP..."
  nmap -sV -p- --open "$EMULATED_IP" 2>&1 | tee "$BASE/nmap_scan.txt" \
    && ok "Résultats → nmap_scan.txt" \
    || warn "Scan nmap échoué (firmware peut-être pas démarré)"
else
  warn "nmap non disponible"
fi

title "Étape 2 : Services actifs"
netstat -tulnp 2>/dev/null | tee "$BASE/netstat.txt" && ok "netstat → netstat.txt"
dmesg 2>/dev/null | tail -20 | tee "$BASE/dmesg.txt" && ok "dmesg → dmesg.txt"

title "Étape 3 : Vulnérabilités à vérifier"
echo ""
echo -e "  ${BOLD}Test credentials par défaut :${RESET}"
for cred in "admin:admin" "admin:password" "admin:" "root:root" "root:admin" "user:user"; do
  USER=$(echo $cred | cut -d: -f1)
  PASS=$(echo $cred | cut -d: -f2)
  RESULT=$(curl -s -o /dev/null -w "%{http_code}" -u "$USER:$PASS" \
    "http://$EMULATED_IP/" --max-time 3 2>/dev/null)
  if [[ "$RESULT" == "200" ]]; then
    echo -e "  ${RED}✘  BACKDOOR: $cred → HTTP $RESULT${RESET}"
  elif [[ "$RESULT" == "000" ]]; then
    echo -e "  ${YELLOW}▸  $cred → service non joignable${RESET}"
  else
    echo -e "  ${GREEN}✔  $cred → HTTP $RESULT (refusé)${RESET}"
  fi
done

echo ""
echo -e "  ${BOLD}Test injection CGI :${RESET}"
CGI_RESULT=$(curl -s "http://$EMULATED_IP/cgi-bin/ping.cgi?host=127.0.0.1;id" \
  --max-time 5 2>/dev/null)
if echo "$CGI_RESULT" | grep -q "uid="; then
  echo -e "  ${RED}✘  INJECTION CGI détectée ! Output: $CGI_RESULT${RESET}"
else
  echo -e "  ${GREEN}✔  Injection CGI non détectée${RESET}"
fi

echo ""
info "Observations sauvegardées dans $BASE/"

# ────────────────────────────────────────────────────────────
banner "TP5 — Patching défensif"

if [[ -z "$EXTRACTED" ]]; then
  warn "Filesystem extrait non trouvé — TP5 limité"
  ROOTFS="$BASE/rootfs_patch"
  mkdir -p "$ROOTFS/etc" "$ROOTFS/bin"
  info "Dossier de travail créé : $ROOTFS"
else
  ROOTFS="$EXTRACTED"
fi

title "Étape 1 : Audit des mots de passe"
if [[ -f "$ROOTFS/etc/passwd" ]]; then
  echo ""
  echo -e "  ${BOLD}Contenu actuel de /etc/passwd :${RESET}"
  cat "$ROOTFS/etc/passwd"
  echo ""
  # Sauvegarde
  cp "$ROOTFS/etc/passwd" "$BASE/passwd.backup"
  ok "Sauvegarde → passwd.backup"

  # Supprime les mots de passe vides ou en clair (champ 2 non vide et non x)
  INSECURE=$(grep -v '^#' "$ROOTFS/etc/passwd" | awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print $1}' 2>/dev/null)
  if [[ -n "$INSECURE" ]]; then
    echo -e "  ${RED}✘  Comptes avec mot de passe en clair détectés : $INSECURE${RESET}"
    info "Correction : remplacement par hash verrouillé (*)"
    sed -i 's/^\([^:]*\):[^:!*x]/\1:*/' "$ROOTFS/etc/passwd" 2>/dev/null
    ok "Mots de passe en clair supprimés"
  else
    ok "Aucun mot de passe en clair détecté"
  fi
fi

title "Étape 2 : Désactivation des services non sécurisés"
for service in telnetd ftpd rshd rlogind; do
  SVC_PATH=$(find "$ROOTFS" -name "$service" -type f 2>/dev/null | head -1)
  if [[ -n "$SVC_PATH" ]]; then
    chmod -x "$SVC_PATH"
    echo -e "  ${RED}✘ → ${GREEN}✔${RESET}  $service désactivé : $SVC_PATH"
  else
    info "$service non trouvé dans le firmware"
  fi
done

title "Étape 3 : Sécurisation des scripts CGI"
CGI_DIR=$(find "$ROOTFS" -type d -name "cgi-bin" 2>/dev/null | head -1)
if [[ -n "$CGI_DIR" ]]; then
  echo -e "  ${BOLD}Scripts CGI trouvés :${RESET}"
  ls "$CGI_DIR/"
  echo ""
  # Cherche les scripts avec des appels shell dangereux
  grep -rl "system\|exec\|popen\|\$_GET\|\$_POST" "$CGI_DIR/" 2>/dev/null | while read f; do
    echo -e "  ${RED}⚠  Appel dangereux dans : $f${RESET}"
  done
  ok "Audit CGI terminé"
else
  info "Dossier cgi-bin non trouvé"
fi

title "Étape 4 : Reconstruction du firmware corrigé"
if command -v mksquashfs &>/dev/null; then
  info "Reconstruction avec mksquashfs..."
  mksquashfs "$ROOTFS" "$BASE/new_firmware_patched.bin" \
    -comp gzip -noappend 2>&1 | tail -3 \
    && ok "Nouveau firmware → $BASE/new_firmware_patched.bin" \
    || warn "mksquashfs échoué"
else
  info "Installation de squashfs-tools..."
  apt-get install -y -qq squashfs-tools 2>/dev/null \
    && mksquashfs "$ROOTFS" "$BASE/new_firmware_patched.bin" -comp gzip -noappend 2>&1 | tail -3 \
    && ok "Nouveau firmware → $BASE/new_firmware_patched.bin" \
    || warn "squashfs-tools non disponible — reconstruction manuelle nécessaire"
fi

# ────────────────────────────────────────────────────────────
banner "Récapitulatif TP3 + TP4 + TP5"

echo -e "  ${BOLD}Dossier de travail : $BASE${RESET}"
echo ""
echo "  Fichiers produits :"
ls "$BASE"/*.txt "$BASE"/*.log "$BASE"/*.bin 2>/dev/null | while read f; do
  [[ "$f" == *firmware.bin ]] && continue
  echo "  ├── $(basename $f)"
done
echo ""
echo -e "  ${BOLD}Commandes utiles pour continuer :${RESET}"
[[ -n "$EMULATED_IP" ]] && echo "  nmap -sV $EMULATED_IP"
[[ -n "$EMULATED_IP" ]] && echo "  curl http://$EMULATED_IP/"
[[ -n "$EXTRACTED" ]]   && echo "  ls $EXTRACTED"
echo ""
echo -e "  ${GREEN}${BOLD}✔  TP3 + TP4 + TP5 terminés !${RESET}"
echo ""
