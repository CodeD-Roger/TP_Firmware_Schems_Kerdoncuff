# Rapport d'analyse — TP Firmware IoT
**Auteur :** user
**Date :** 01/04/2026 10:16
**Machine :** user — 6.8.0-106-generic
**Dossier d'analyse :** /home/user/IoT/formation-Jour2/firmware-analysis

---
## TP1+TP2 — Analyse statique & Reverse engineering

### Outils installés

| Outil | Statut | Version |
|---|---|---|
| `binwalk` | ✔ Présent |  |
| `strings` | ✔ Présent | GNU strings (GNU Binutils for Ubuntu) 2.42 |
| `file` | ✔ Présent | file-5.45 |
| `readelf` | ✔ Présent | GNU readelf (GNU Binutils for Ubuntu) 2.42 |
| `radare2` | ✔ Présent |  |

### Firmware et extraction

- **firmware.bin** : présent (3,8M)
- **Filesystem extrait** : /home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root (675 fichiers)
- **Signatures Binwalk** : 2 détectées

#### Sortie Binwalk
```

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
512           0x200           LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 3292900 bytes
1107552       0x10E660        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2148698 bytes, 950 inodes, blocksize: 262144 bytes, created: 2014-10-02 07:08:37

```

### Architecture CPU détectée
```
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/init: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/procd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/mtd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
```

### Binaires ELF trouvés

**118 binaires ELF** identifiés dans le firmware :
```
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/init: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/procd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/mtd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/kmodloader: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/netifd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/logd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/logread: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/fw3: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/jffs2reset: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/snapshot_tool: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/ubusd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/mount_root: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/udevtrigger: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/uci: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/askfirst: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/swconfig: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/sbin/validate_data: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/bin/ubus: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/bin/opkg: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libfstools.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libubus.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libutil-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libgcc_s.so.1: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip6table_filter.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ipt_MASQUERADE.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_conntrack_ipv4.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/compat.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_CT.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip_tables.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_REDIRECT.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_conntrack_irc.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/cfg80211.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/iptable_raw.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ipt_REJECT.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ipv6.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/iptable_nat.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip6table_mangle.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ath9k_hw.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_conntrack.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/pppoe.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_tcpudp.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/iptable_mangle.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_limit.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip6t_REJECT.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ppp_generic.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_LOG.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ath9k_common.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/iptable_filter.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/crc-ccitt.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_mac.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/arc4.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_nat.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_mark.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/slhc.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_nat_irc.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_nat.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_id.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip6table_raw.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_nat_ipv4.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_conntrack_ftp.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_conntrack_ipv6.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_TCPMSS.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/crypto_blkcipher.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_multiport.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_conntrack.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ath9k.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/gpio-button-hotplug.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ppp_async.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/x_tables.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/mac80211.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ip6_tables.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_defrag_ipv6.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_state.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/pppox.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_defrag_ipv4.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_time.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/xt_comment.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/ath.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/modules/3.10.49/nf_nat_ftp.ko: ELF 32-bit MSB relocatable, MIPS, MIPS32 rel2 version 1 (SYSV), not stripped
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libdl-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libuClibc-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libcrypt-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libblobmsg_json.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libubox.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libvalidate.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libjson_script.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/ld-uClibc-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), static-pie linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libm-0.9.33.2.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/lib/libuci.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/wpad: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/uhttpd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/xtables-multi: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/pppd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/iw: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/odhcpd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/dnsmasq: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/odhcp6c: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/dropbear: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/sbin/fw_printenv: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/bin/luci-bwc: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/bin/lua: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/bin/jsonfilter: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/bin/jshn: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libnl-tiny.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libip4tc.so.0.1.0: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/lua/nixio.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/lua/luci/template/parser.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/lua/uci.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/lua/iwinfo.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/lua/ubus.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/pppd/2.4.7/rp-pppoe.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libiwinfo.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/liblua.so.5.1.5: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libip6tc.so.0.1.0: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/uhttpd_ubus.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libjson-c.so.2.0.1: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
/home/user/IoT/formation-Jour2/firmware-analysis/_firmware.bin.extracted/squashfs-root/usr/lib/libxtables.so.10.0.0: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, no section header
```

### Analyse strings — résultats critiques

#### uhttpd — shell (1 lignes)
```
#!/bin/sh /etc/rc.common
```

#### uhttpd — etc (3 lignes)
```
#!/bin/sh /etc/rc.common
	config_get UHTTPD_KEY  "$cfg" key  /etc/uhttpd.key
	config_get UHTTPD_CERT "$cfg" cert /etc/uhttpd.crt
```

#### Radare2 — fonctions de uhttpd (1 fonctions)
```
0x00000000    1 2            fcn.00000000
```

### Contenu /etc/passwd du firmware

- Aucun mot de passe en clair
```
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
```

---
## TP3 — Émulation Firmadyne + QEMU

| `qemu-system-mips` | ✔ Présent | QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.13) |
| `qemu-system-arm` | ✔ Présent | QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.13) |
- **Firmadyne** : cloné (11cb574 update dockerfile to use ubuntu 22.04 (#219))
- **Architecture** : voir section TP1
- **IP émulée** : ⚠ non détectée

### Log de démarrage QEMU (50 premières lignes)
```
./firmadyne.config: line 7: FIRMWARE_DIR: unbound variable
```

---
## TP4 — Analyse dynamique

### Scan nmap — 0
0 ports ouverts
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-01 10:14 UTC
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.18 seconds
```

### Services réseau actifs (netstat)
```
```

### Vulnérabilités identifiées

- **Telnet** : telnetd présent mais désactivé (patché)
- **Injection shell** : ⚠ 1 références à /bin/sh ou system() dans les binaires

---
## TP5 — Patching défensif

- **Backup /etc/passwd** : présent
- **Firmware patché** : ✔ présent (4,0K)
- **Taille originale** : 3,8M
- **Taille patchée** : 4,0K
- **Telnetd** : ⚠ encore exécutable (chmod -x non appliqué)

---
## Inventaire des fichiers produits

| Fichier | Taille | Statut |
|---|---|---|
| `binwalk_analyse.txt` | 4,0K | ✔ Présent |
| `binwalk_extraction.log` | 8,0K | ✔ Présent |
| `elf_files.txt` | 28K | ✔ Présent |
| `architecture.txt` | 4,0K | ✔ Présent |
| `nmap_scan.txt` | 4,0K | ✔ Présent |
| `netstat.txt` | 0 | ✔ Présent |
| `dmesg.txt` | 4,0K | ✔ Présent |
| `passwd.backup` | 4,0K | ✔ Présent |
| `new_firmware_patched.bin` | 4,0K | ✔ Présent |

---
## Résultats des tests

| | Résultat |
|---|---|
| ✔ Tests réussis | 35 / 38 |
| ✘ Tests échoués | 2 / 38 |
| ⚠ Avertissements | 1 / 38 |

> Rapport généré le 01/04/2026 à 10:16 par `test_and_report.sh`
