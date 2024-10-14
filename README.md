# Masterarbeit: Adversary Emulation zum Vergleich des Sicherheitsniveaus verschiedener Systemkonfigurationen und -versionen in Windows-Umgebungen

Dieses Repository enthält die prototypische Implementierung meiner Masterarbeit. Die Implementierung verwendet das Adversary Emulation Tool Caldera.

Kurzzusammenfassung:

- Es wurde eine Methodik entwickelt, die mittels Adversary Emulation Windows-Systeme angreift und anhand der Ergebnisse das Sicherheitsniveau der Systemkonfiguration vergleicht.
- Teil der Methodik ist ein auf dem Vergleich aufbauendes iteratives Verfahren, dass schrittweise einzelne Konfigurationseinstellungen auf einem System setzt und einen Emulationsdurchlauf ausführt. Anhand der Emulationsergebnisse wird ermittelt, ob die einzelne Einstellung oder Einstellungskombinationen der gesetzten Einstellung eine Auswirkung auf das Sicherheitsniveau des Systems hat. Ansatt zwei verschiedene Systeme zu vergleichen, werden hier zwei Konfigurationsstände des selben Systems verglichen.
- Für die implementierung der Angriffe und Ausführung der Angriffsemulation wird das Tool Caldera verwendet.

## compare_caldera_results.ps1
Dieses Skript parst bereits vorliegende Caldera Angriffsergebnisse für zwei verschiedene Systeme und vergleicht die Systeme anhand der Anzahl erfolgreicher Angriffe, um das Sicherheitsniveau zu vergleichen. Zusätzlich wird ermittelt, welche Angriffe einen unterschiedlichen Erfolgsstatus aufweisen.

## combination_adjusted.psm1
Dieses Powershell-Modul wurde nicht selbst entwickelt und stammt von 'dfinke' (https://github.com/dfinke/PowerShellCombinations). Das Modul kann Kombinationen belieber Größe generieren (Bsp.: 3er-Kombinatonen aus 5 Input-Objecten = 10 verschiedene Kombinationen).
Das Modul wurde leicht angepasst, sodass nicht nur String Arrays unterstützt werden. Es wurde so angepasst, dass es PowerShell-Objekte verarbeiten kann und alle ermittelten Kombinationen als Liste zurückgibt, die wiederum Listen mit den jeweiligen Powershell-Objekt-Kombinationen enthält.
Das Modul wird im Skript des iterativen Verfahrens verwendet, um die Einstellungskombinationen zu bilden, die untersucht werden sollen.

## caldera_api.psm1
Dieses Powershell-Modul enthält Hilfsfunktionen, um API-Endpunkte der Caldera-API aufzurufen und damit Aktionen auszuführen.
Das Modul wird zur Automatisierung des iterativen Verfahrens verwendet, um Angriffsdurchläufe in Caldera zu starten und die Ergebnisse abzurufen und auszuwerten.

## iterative_method_automation.ps1
Dieses PowerShell-Skript implementiert und automatisiert das iterative Verfahren. Es importiert die zwei Module 'caldera_api.psm1' und 'combination_adjusted.psm1'.
Das Skript orchestriert den kompletten Ablauf und besitzt 2 Betriebsmodi:

* Isolated: Setzt jede einzelne Registry-Einstellung auf den Ausgangszustand. Macht also jede Einstellung nach dem Emulationsdurchlauf wieder rückgängig.
* Addtive: Macht eine gesetzte Registry-Einstellung nicht rückgängig, sondern setzt die nächste Einstellung. Somit können Auswirkungen von Einstellungskombinationen erkannt werden.

Im Skript muss der Pfad zu einer CSV-Datei spezifiziert werden, die die entsprechenden Registry-Einstellungen enthält. Die Datei muss folgendem Format folgen (Beispiel mit 2 Einstellungen):
```
"KeyName","ValueName","ValueType","ValueLength","ValueData"
"HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableRealtimeMonitoring","REG_DWORD","4","1"
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","RunAsPPL","REG_DWORD","4","0"
```

Zudem müssen im Skript die zu verwendenden Caldera Angriffsprofile und die entsprechenden Caldera Agents in folgenden Format angegeben werden:
```
Key: Agent Group, Value: Adversary Profile
$script:AttackPlans = @{"Win11-23H2-User" = "Windows Hardening Test - User Scope"; 
                        "Win11-23H2-System" = "Windows Hardening Test - System Scope";
}
```

Das Skript baut eine über PowerShell-Remoting-over-SSH eine Verbindung zum Zielsystem auf und triggert Aktionen auf dem Caldera-Server über die API-Hilfsfunktionen. Über die SSH-Verbindung wird eine Einstellung gesetzt und dann ein Emulationsdurchlauf von Caldera getriggert. Wenn dieser beendet ist, werden die Ergebnisse abgerufen und mit den Ergebnisse des letzten Zustand verglichen, um Auswirkungen zu untersuchen und ggf. verantwortliche Einstellungskombinationen zu ermitteln. Dies geschieht solange, bis alle zu setzenden Einstellungen abgearbeitet wurden.



