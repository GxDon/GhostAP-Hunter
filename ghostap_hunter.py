#!/usr/bin/env python3

import subprocess
import time
from collections import defaultdict


INTERVAL = 10

known_networks = defaultdict(set)


def ejecutar_nmcli():
    command = [
        "nmcli",
        "-t",
        "--escape",
        "yes",
        "-f",
        "SSID,BSSID,SECURITY,SIGNAL",
        "device",
        "wifi",
        "list",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )

    except FileNotFoundError:
        print(
            "[!] nmcli no está instalado."
        )
        return []

    except subprocess.TimeoutExpired:
        print("[!] nmcli tardó demasiado.")
        return []

    if result.returncode != 0:
        error = result.stderr.strip()

        if error:
            print(f"[!] nmcli: {error}")

        return []

    return result.stdout.splitlines()


def separar_nmcli(line):
    fields = []
    current = []
    escaped = False

    for char in line:

        if escaped:
            current.append(char)
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if char == ":":
            fields.append("".join(current))
            current = []
            continue

        current.append(char)

    fields.append("".join(current))

    return fields


def scan():
    lines = ejecutar_nmcli()

    networks = []

    for line in lines:

        if not line.strip():
            continue

        parts = separar_nmcli(line)

        if len(parts) != 4:
            continue

        ssid, bssid, security, signal = parts

        networks.append({
            "ssid": ssid or "<OCULTA>",
            "bssid": bssid.upper(),
            "security": security.upper(),
            "signal": signal
        })

    return networks


def analizar(networks):
    print()
    print("🧠 Analizando redes detectadas...")
    print()

    if not networks:
        print("[!] No se detectaron redes.")
        return

    for network in networks:

        ssid = network["ssid"]
        bssid = network["bssid"]
        security = network["security"]

        known_networks[ssid].add(bssid)

        print(
            f"SSID: {ssid} | "
            f"BSSID: {bssid} | "
            f"Seguridad: {security} | "
            f"Señal: {network['signal']}"
        )

        if len(known_networks[ssid]) > 1:
            print(
                f"  🚨 POSIBLE CAMBIO DE BSSID: "
                f"{ssid}"
            )

        if security in ("", "--"):
            print("  ⚠️ RED ABIERTA")

        elif "WEP" in security:
            print("  ⚠️ WEP inseguro")

        elif "WPA1" in security:
            print("  ⚠️ WPA1 obsoleto")

        else:
            print("  ✅ Seguridad no detectada como débil")

        print()


def monitor():
    print("=" * 60)
    print("                GhostAP-Hunter")
    print("             Monitor WiFi pasivo")
    print("=" * 60)

    print(
        "[+] El análisis utiliza información "
        "proporcionada por NetworkManager."
    )

    print(
        "[+] Presiona Ctrl+C para terminar."
    )

    while True:

        try:
            networks = scan()

            analizar(networks)

            time.sleep(INTERVAL)

        except KeyboardInterrupt:
            print()
            print("[+] Monitoreo detenido.")
            break

        except Exception as error:
            print(
                f"[!] Error inesperado: {error}"
            )

            time.sleep(INTERVAL)


if __name__ == "__main__":
    monitor()