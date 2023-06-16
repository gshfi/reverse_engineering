## Network Scanning Simulation/automation:

import subprocess

# Niveau keuze
print("Welkom bij de Network Scanning Simulation/automation!")
print("Met dit script kun je een netwerk scan uitvoeren.")
print("Er zijn vijf verschillende niveaus waaruit je kunt kiezen, afhankelijk van de gewenste informatie en het netwerkverkeer.")
print("Voer hieronder eerst de gewenste doelwit")

ip_adres = input("Geef een IP-adres op: ")

keuze = input("Kies je niveau (1-5): ")

if keuze == "1":
    ## Dit commando voert een "Stealth TCP Scan" uit op het opgegeven IP-adres.
    # Het voert een verbindingstest uit met behulp van TCP-pakketten om open poorten op het IP-adres te identificeren.
    # Het voert ook een OS-detectie uit om te proberen het besturingssysteem dat op het IP-adres draait te identificeren.
    # Het voert de scan uit met een vertraging van 1 seconde tussen elk verzonden pakket om de netwerkbelasting te beperken.
    command1 = "nmap -sT -O -v -T1 {ip_adres}"
    subprocess.run(command1, shell=True)
    print("Niveau 1 klaar!")

elif keuze == "2":
    ## Dit commando voert een "Service Scan" uit op het opgegeven IP-adres. Het voert een verbindingstest uit met behulp van TCP-pakketten om open poorten te identificeren. Vervolgens probeert het de versie van de services die op deze poorten luisteren te achterhalen. Het voert de scan uit met een vertraging van 4 seconden tussen elk verzonden pakket. Het scant alle poorten en geeft alleen de open poorten weer. Het voert de scan uit met extra verbose-output en slaat de scanresultaten op in een bestand met de naam "nmap_scan_results".
    command2 = f"nmap -sV -T4 -p- --open -n -vv -oA \"nmap_scan_results\" {ip_adres}"
    subprocess.run(command2, shell=True)
    print("Niveau 2 klaar!")

elif keuze == "3":
    ## Dit commando voert een "Service Scan" uit, met extra informatie zoals OS-detectie, traceroute-informatie en scripting-output. Het voert een verbindingstest uit met behulp van TCP-pakketten om open poorten te identificeren. Vervolgens probeert het de versie van de services die op deze poorten luisteren te achterhalen. Het voert de scan uit met een vertraging van 4 seconden tussen elk verzonden pakket. Het scant alle poorten in het bereik van 1-65535.
    command3 = f"nmap -T4 -A -v -sV -p 1-65535 {ip_adres}"
    subprocess.run(command3, shell=True)
    print("Niveau 3 klaar!")

elif keuze == "4":
    ## Dit commando voert een "Aggressive Scan" uit op het opgegeven IP-adres. Het voert een verbindingstest uit met behulp van TCP-pakketten om open poorten te identificeren. Vervolgens probeert het de versie van de services die op deze poorten luisteren te achterhalen. Het voert ook een OS-detectie uit, traceroute-informatie en scripting-output. Het voert de scan uit met een vertraging van 4 seconden tussen elk verzonden pakket.
    command4 = f"nmap -A -T4 {ip_adres}"
    subprocess.run(command4, shell=True)
    print("Niveau 4 klaar!")

elif keuze == "5":
    ## Dit commando voert een "Extreme Loud Scan" uit op het opgegeven IP-adres. Het voert een verbindingstest uit met behulp van TCP-pakketten om open poorten te identificeren. Vervolgens probeert het de versie van de services die op deze poorten luisteren te achterhalen. Het voert ook een OS-detectie uit, traceroute-informatie en scripting-output. Het voert de scan uit met een vertraging van 5 seconden tussen elk verzonden pakket.
    command5 = f"nmap -v -A -T5 {ip_adres}"
    subprocess.run(command5, shell=True)
    print("Niveau 5 klaar!")

print("Klaar met uitvoeren!")