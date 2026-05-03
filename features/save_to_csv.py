"""
Projet NAC - Système intelligent de gestion des accès réseau
============================================================
Script  : features/save_to_csv.py
Rôle    : Capturer le trafic réseau et constituer un dataset CSV
Auteur  : PFE NAC / Machine Learning
"""

import csv
import os
from datetime import datetime
from scapy.all import sniff, IP

# ─────────────────────────────────────────────
#  CONFIGURATION GLOBALE
# ─────────────────────────────────────────────

# Chemin absolu robuste (fonctionne depuis n'importe où)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FICHIER_CSV = os.path.join(BASE_DIR, "data", "traffic.csv")

NOMBRE_PAQUETS = 20

EN_TETES = ["timestamp", "ip_source", "ip_destination", "protocole", "taille"]

# Correspondance protocole IP → nom lisible
TABLE_PROTOCOLES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# ─────────────────────────────────────────────
#  1. INITIALISATION DU FICHIER CSV
# ─────────────────────────────────────────────
def initialiser_csv(chemin: str) -> None:
    fichier_vide = (
        not os.path.isfile(chemin)
        or os.path.getsize(chemin) == 0
    )

    if fichier_vide:
        with open(chemin, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(EN_TETES)
        print(f"[+] Fichier CSV initialisé : {chemin}")
    else:
        print(f"[~] Fichier existant — ajout des données : {chemin}")

# ─────────────────────────────────────────────
#  2. ENREGISTREMENT D'UNE LIGNE
# ─────────────────────────────────────────────
def enregistrer_ligne(chemin: str, donnees: dict) -> None:
    with open(chemin, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EN_TETES)
        writer.writerow(donnees)

# ─────────────────────────────────────────────
#  3. TRAITEMENT D'UN PAQUET
# ─────────────────────────────────────────────
def traiter_paquet(paquet) -> None:
    if not paquet.haslayer(IP):
        return

    couche_ip = paquet[IP]

    protocole = TABLE_PROTOCOLES.get(
        couche_ip.proto,
        f"AUTRE({couche_ip.proto})"
    )

    ligne = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_source": couche_ip.src,
        "ip_destination": couche_ip.dst,
        "protocole": protocole,
        "taille": len(paquet),
    }

    # Affichage console
    print(
        f"{ligne['timestamp']} | "
        f"{ligne['ip_source']} → {ligne['ip_destination']} | "
        f"{ligne['protocole']} | {ligne['taille']} octets"
    )

    # Sauvegarde CSV
    enregistrer_ligne(FICHIER_CSV, ligne)

# ─────────────────────────────────────────────
#  4. MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print(" NAC — Capture réseau → CSV ")
    print("=" * 60)

    # Vérification dossier data
    data_dir = os.path.join(BASE_DIR, "data")
    if not os.path.isdir(data_dir):
        print("[ERREUR] Dossier 'data/' introuvable.")
        return

    initialiser_csv(FICHIER_CSV)

    print(f"\n[*] Capture de {NOMBRE_PAQUETS} paquets...\n")

    try:
        sniff(
            prn=traiter_paquet,
            count=NOMBRE_PAQUETS,
            store=False,
            filter="ip"   # 🔥 filtre PRO
        )
    except PermissionError:
        print("[ERREUR] Lance avec sudo :")
        print("sudo venv/bin/python nac-intelligent-ml/features/save_to_csv.py")

    print(f"\n[✓] Données enregistrées dans : {FICHIER_CSV}\n")

# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()