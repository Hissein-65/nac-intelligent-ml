# =============================================================================
# PROJET : Système NAC Intelligent
# MODULE  : Capture du trafic réseau
# FICHIER : capture/capture_traffic.py
# AUTEUR  : Étudiant L3 Informatique
# =============================================================================
# DESCRIPTION :
#   Ce script capture les paquets réseau en temps réel à l'aide de Scapy.
#   Il affiche les informations essentielles de chaque paquet :
#   adresse IP source, adresse IP destination, et le protocole utilisé.
#
#   C'est la PREMIÈRE BRIQUE du système NAC : sans capture, pas d'analyse !
# =============================================================================

# --- IMPORTATION DES BIBLIOTHÈQUES ---

# 'scapy.all' contient tout ce dont on a besoin pour capturer et analyser
# les paquets réseau (IP, TCP, UDP, ICMP, etc.)
from scapy.all import sniff, IP, TCP, UDP, ICMP

# 'datetime' permet d'afficher l'heure exacte de capture de chaque paquet
from datetime import datetime


# =============================================================================
# FONCTION : identifier_protocole
# Rôle     : Détermine le nom du protocole d'un paquet (TCP, UDP, ICMP...)
# =============================================================================
def identifier_protocole(paquet):
    """
    Analyse les couches du paquet pour identifier son protocole.
    Retourne une chaîne de caractères : 'TCP', 'UDP', 'ICMP' ou 'Autre'.
    """

    if paquet.haslayer(TCP):
        return "TCP"
    elif paquet.haslayer(UDP):
        return "UDP"
    elif paquet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Autre"


# =============================================================================
# FONCTION : traiter_paquet
# Rôle     : Appelée automatiquement par Scapy pour CHAQUE paquet capturé.
#            Elle extrait et affiche les informations utiles.
# =============================================================================
def traiter_paquet(paquet):
    """
    Callback appelé par sniff() à chaque nouveau paquet reçu.
    Extrait : timestamp, IP source, IP destination, protocole.
    """

    # On vérifie que le paquet contient bien une couche IP
    # (certains paquets réseau sont de bas niveau et n'ont pas d'IP)
    if paquet.haslayer(IP):

        # --- EXTRACTION DES INFORMATIONS ---

        # Heure actuelle formatée (ex: 14:32:05)
        horodatage = datetime.now().strftime("%H:%M:%S")

        # Adresse IP de l'expéditeur (source)
        ip_source = paquet[IP].src

        # Adresse IP du destinataire (destination)
        ip_destination = paquet[IP].dst

        # Protocole du paquet (TCP / UDP / ICMP / Autre)
        protocole = identifier_protocole(paquet)

        # Taille du paquet en octets
        taille = len(paquet)

        # --- AFFICHAGE FORMATÉ ---
        # On affiche une ligne lisible pour chaque paquet capturé
        print(f"[{horodatage}]  {ip_source:<18} → {ip_destination:<18}  "
              f"Protocole: {protocole:<6}  Taille: {taille} octets")

    else:
        # Paquet sans couche IP (ex: ARP, Ethernet pur...)
        # On l'indique mais on ne l'analyse pas en détail
        print(f"[{datetime.now().strftime('%H:%M:%S')}]  "
              f"Paquet non-IP détecté : {paquet.summary()}")


# =============================================================================
# FONCTION PRINCIPALE : lancer_capture
# Rôle : Configure et démarre la capture réseau
# =============================================================================
def lancer_capture(nb_paquets=10, interface=None):
    """
    Lance la capture réseau.

    Paramètres :
        nb_paquets  (int)  : nombre de paquets à capturer (défaut: 10)
        interface   (str)  : interface réseau à écouter (défaut: auto)
                             Exemples : 'eth0', 'wlan0', 'lo'
    """

    # --- EN-TÊTE D'AFFICHAGE ---
    print("=" * 70)
    print("   SYSTÈME NAC - MODULE DE CAPTURE DU TRAFIC RÉSEAU")
    print("=" * 70)
    print(f"  Nombre de paquets à capturer : {nb_paquets}")
    print(f"  Interface réseau             : {interface if interface else 'Automatique'}")
    print("=" * 70)
    print(f"  {'HEURE':<10} {'IP SOURCE':<20} {'IP DESTINATION':<20} "
          f"{'PROTO':<10} {'TAILLE'}")
    print("-" * 70)

    # --- LANCEMENT DE LA CAPTURE ---
    # sniff() est la fonction principale de Scapy pour capturer des paquets.
    #
    # Arguments :
    #   prn     = la fonction à appeler pour chaque paquet (notre callback)
    #   count   = nombre de paquets à capturer avant de s'arrêter
    #   iface   = interface réseau (None = Scapy choisit automatiquement)
    #   store   = False → ne pas stocker les paquets en mémoire (économie RAM)
    #
    try:
        sniff(
            prn=traiter_paquet,   # Appelle traiter_paquet() pour chaque paquet
            count=nb_paquets,     # S'arrête après nb_paquets paquets
            iface=interface,      # Interface réseau (None = auto)
            store=False,         # Ne pas garder les paquets en mémoire
            filter="ip"           #Ajoute un filtre pour éviter le bruit 
        )
    except PermissionError:
        # Scapy nécessite des droits root/administrateur pour capturer
        print("\n  [ERREUR] Permission refusée.")
        print("  → Commande : sudo python3 capture/capture_traffic.py")
    except OSError as e:
        # Interface introuvable ou autre erreur système
        print(f"\n  [ERREUR] Problème d'interface réseau : {e}")
        print("  → Vérifiez le nom de l'interface avec : ip link show")

    # --- RÉSUMÉ FINAL ---
    print("-" * 70)
    print(f"  Capture terminée. {nb_paquets} paquets analysés.")
    print("=" * 70)


# =============================================================================
# POINT D'ENTRÉE DU SCRIPT
# Ce bloc s'exécute uniquement quand on lance le fichier directement
# (pas quand il est importé comme module dans un autre script)
# =============================================================================
if __name__ == "__main__":

    # Lancement de la capture avec 10 paquets sur l'interface automatique.
    # Pour spécifier une interface : lancer_capture(nb_paquets=10, interface="eth0")
    lancer_capture(nb_paquets=10)