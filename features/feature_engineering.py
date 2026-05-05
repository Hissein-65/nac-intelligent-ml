"""
Projet NAC - Système intelligent de gestion des accès réseau
============================================================
Script  : features/feature_engineering.py
Rôle    : Transformer traffic.csv en features numériques pour le ML
Entrée  : data/traffic.csv
Sortie  : data/features.csv
"""

import os
import pandas as pd

# ─────────────────────────────────────────────
#  CONFIGURATION (CHEMINS ROBUSTES)
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FICHIER_ENTREE = os.path.join(BASE_DIR, "data", "traffic.csv")
FICHIER_SORTIE = os.path.join(BASE_DIR, "data", "features.csv")


# ─────────────────────────────────────────────
#  1. CHARGEMENT DES DONNÉES
# ─────────────────────────────────────────────
def charger_donnees(chemin: str) -> pd.DataFrame:
    if not os.path.isfile(chemin):
        print(f"[ERREUR] Fichier introuvable : {chemin}")
        print("Lance d'abord save_to_csv.py pour générer les données.")
        exit(1)

    df = pd.read_csv(chemin)
    print(f"[+] Données chargées : {len(df)} lignes")
    return df


# ─────────────────────────────────────────────
#  2. NETTOYAGE DES DONNÉES
# ─────────────────────────────────────────────
def nettoyer_donnees(df: pd.DataFrame) -> pd.DataFrame:
    avant = len(df)

    df = df.dropna(how="all")
    df = df.drop_duplicates()
    df = df.dropna(subset=["taille", "protocole"])

    # sécurisation + normalisation
    df["protocole"] = df["protocole"].astype(str)
    df.loc[:, "protocole"] = df["protocole"].str.upper().str.strip()

    apres = len(df)
    print(f"[~] Nettoyage : {avant} → {apres} lignes")

    return df


# ─────────────────────────────────────────────
#  3. CALCUL DES FEATURES
# ─────────────────────────────────────────────
def calculer_features(df: pd.DataFrame) -> dict:
    features = {
        "total_paquets": len(df),

        "taille_moyenne": round(df["taille"].mean(), 2),
        "taille_max": int(df["taille"].max()),
        "taille_min": int(df["taille"].min()),

        "protocole_TCP": int(df["protocole"].value_counts().get("TCP", 0)),
        "protocole_UDP": int(df["protocole"].value_counts().get("UDP", 0)),
        "protocole_ICMP": int(df["protocole"].value_counts().get("ICMP", 0)),
    }

    return features


# ─────────────────────────────────────────────
#  4. SAUVEGARDE DES FEATURES
# ─────────────────────────────────────────────
def sauvegarder_features(features: dict, chemin: str) -> None:
    df_features = pd.DataFrame([features])
    df_features.to_csv(chemin, index=False)
    print(f"[✓] Features sauvegardées : {chemin}")


# ─────────────────────────────────────────────
#  5. AFFICHAGE
# ─────────────────────────────────────────────
def afficher_resume(features: dict) -> None:
    print("\n--- FEATURES EXTRAITES ---")
    for k, v in features.items():
        print(f"{k} : {v}")
    print("--------------------------\n")


# ─────────────────────────────────────────────
#  6. MAIN
# ─────────────────────────────────────────────
def main():
    print("=== NAC - Feature Engineering ===\n")

    df = charger_donnees(FICHIER_ENTREE)
    df = nettoyer_donnees(df)

    features = calculer_features(df)

    afficher_resume(features)

    sauvegarder_features(features, FICHIER_SORTIE)

    print("Prochaine étape → Machine Learning")


# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()