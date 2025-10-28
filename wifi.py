#!/usr/bin/env python3
import re
import json
import argparse
import datetime

from pathlib import Path
import pandas as pd
import numpy as np

# -- 1) Charger le fichier JSON (dépendances)
# wifi.py — remplace read_json par la version tolérante
def read_json(path: str):
    try:
        import json5
        with open(path, "r", encoding="utf-8") as f:
            return json5.load(f)   # accepte //, virgules finales, etc.
    except ModuleNotFoundError:
        import json, re
        txt = open(path, "r", encoding="utf-8").read()
        # nettoyages minimaux si json5 n’est pas dispo
        txt = re.sub(r'//.*', '', txt)                       # enlève // commentaires
        txt = re.sub(r',(\s*[}\]])', r'\1', txt)             # enlève virgules finales
        return json.loads(txt)

def write_csv(df, out_path):
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H%M%S")
    df.to_csv(out_path, index=False, date_format="%Y-%m-%d %H:%M:%S", header=True)
# Extraction sûre : garde la chaîne et récupère le chiffre si présent

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CSV d'inventaire (baseline) avec scores heuristiques pour rouge AP.")
    ap.add_argument("--input-json", required=True,
                    help="Fichier JSON à analyser")
    ap.add_argument("--output-csv", default="inventaire_baselines.csv",
                    help="Export CSV d'inventaire (date, BSSID/OUI, SSID, canal, métadonnées + scores)")
    args = ap.parse_args()

    # -- 2) Charger le JSON
    data = read_json(args.input_json)

    # -- 3) Créer les données à partir du JSON
    columns = [
        "date", "bssid", "oui_vendor",
        "ssid", "chan",
        "bandwidth", "bandwidth_mhz",
        "beacon_int", "rssi_dbm",
        "ie_keys", "rsn_ies",
        "entropy_penalty"
    ]


    rows = []
    for row in data:
        date_str = row.get("timestamp")
        bssid = row.get("mac_addr", "")
        oui = row.get("vendor", "")

        # RSN IE et autres métadonnées
        rsn_ies = row.get("ie_info", "").get("RSN", [])
        ie_keys = list(row["ie_info"].keys())

        if "beacon_int" in row:
            beacon_int = float(row["beacon_int"])
        else:
            beacon_int = np.nan

        # Entropy de l'SSID (score bonus/penalty)
        try:
            entropy = int(len(bssid) * 2.5)
        except Exception:
            entropy = np.nan
        ent_penalty = min(entropy, 100)
        # Extraction sûre : garde la chaîne et récupère le chiffre si présent

        bw_raw = str(row.get("bandwidth", "")).strip()   # exemple: "HT/20"
        bw_mhz = None
        m = re.search(r'(\d+)', bw_raw)
        if m:
            bw_mhz = int(m.group(1))   # extrait 20 de "HT/20"


        rows.append({
            "date": date_str,
            "bssid": bssid[:8],          # Afficher une partie pour humains
            "oui_vendor": oui,           # OUI ou None
            "ssid": row["ssid"],
            "chan": row.get("channel", ""),
            "bandwidth": bw_raw,            # la valeur brute, ex: "HT/20"
            "bandwidth_mhz": bw_mhz,        # numérique (20) ou None
            "beacon_int": beacon_int,
            "rssi_dbm": float(row.get("rssis", {}).get("all", [np.nan])[0]),  # Utiliser la meilleure valeur
            "ie_keys": ie_keys,
            "rsn_ies": str(rsn_ies)[:60],
            "entropy_penalty": ent_penalty
        })

    df = pd.DataFrame(rows, columns=columns)
    df["date"] = pd.to_datetime(df.date).dt.tz_localize(None)

    # -- 4) Scores heuristiques (scores + alertes)
    # - RSN mismatch vs baselines
    # - BSSID/OUI inattendu
    # - Multi-channel (beacons sur >1 canaux avec SSID identique)
    # - Timing anormal
    # - Canal/rssi variables dans un laps de temps court
    def match_oui(ssid, vendor):
        base_vendor = {"Aironet": "00:04:5A",  # Cisco/Aruba
                       "Ralink": "00:2B:81"}
        for key in base_vendor:
            if key.lower() in ssid.lower():
                return True
        return False

    def compute_scores(row):
        oui = row["oui_vendor"]
        vendor_match = match_oui(row["ssid"], oui)
        scores = {
            "ouinomismatch": 0,
            "rsnmismatch": 0,
            "multi_channel": 0,
            "timing_anomalie": 0,
            "entropy_penalty": -row["entropy_penalty"],
            "total_score": 0
        }

        # BSSID/OUI
        if vendor_match is not None and not vendor_match:
            scores["ouinomismatch"] = 3

        # RSN IE (dans les métadonnées)
        rsn_ies = row["rsn_ies"]
        base_expected = {
            "WPA2": "RSNIE:AuthAlg=CCMP",
            "WPA3": "RSNIE:AuthAlg=OWE",
            "WEP": "",   # WEP a souvent des IEs plus vides
            "WPA/TKIP": "RSNIE:AuthAlg=TSC"
        }
        expected_ies = []
        for k in base_expected:
            if "WEP" in k.lower():
                expected_ies.append("WEP")
            else:
                # Simplifier pour démonstration — dans un vrai script on aurait une correspondance complète
                # et des regex sur les champs (CipherSuite)
                expected_ies.append(k.upper())

        for ie_type in rsn_ies:
            if ie_type in expected_ies:
                scores["rsnmismatch"] = 0

        # Multi-channel
        if row["bandwidth"].startswith("40") or \
           row["bandwidth"].startswith("80") or \
           row.get("multi_channel"):
            scores["multi_channel"] = 2

        # Timing anormal (beacon interval hors intervalles légaux)
        timing_ok = False
        try:
            if float(row["beacon_int"]) >= 10.000 and \
               float(row["beacon_int"]) <= 10000:   # 0.010–10s (décimation possible, valeurs légales ~30-200ms)
                timing_ok = True
        except Exception as e:
            pass

        if not timing_ok:
            scores["timing_anomalie"] = 3

        # Total score (pondération + penalty)
        scores["total_score"] = max(scores.values())

        return scores

    df_scores = df.apply(compute_scores, axis=1)

    # -- 5) Exporter en CSV
    write_csv(df, args.output_csv)
