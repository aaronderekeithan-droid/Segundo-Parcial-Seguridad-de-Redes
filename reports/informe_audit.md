# Informe de auditoria CIS (modo audit, sin cambios)

- Fecha: 2026-11-13_23-13-58
- Benchmark: CIS Cisco IOS 15 v4.1.1 (R1, SW1) y CIS FortiGate (FW1)
- Estudiante: Aaron Hernandez (2025-0800)

## Resumen

| Equipo | Cumple | Total | % |
|---|---|---|---|
| R1 | 18 | 18 | 100 % |
| SW1 | 18 | 18 | 100 % |

## R1

| ID CIS | Control | Estado | Evidencia | Por que |
|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | CUMPLE | line vty 0 4: transport input ssh | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. |
| 1.2.4 | Create 'access-list' for use with 'line vty' | CUMPLE | VTY-ACL: permit 10.8.25.11 / deny   any log | Define quien puede administrar el equipo: solo la estacion ADMIN. |
| 1.2.5 | Set 'access-class' for 'line vty' | CUMPLE | line vty 0 4: access-class VTY-ACL in | Sin access-class, cualquier host de la red puede intentar entrar por vty. |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | CUMPLE | line con 0: exec-timeout 10 0 (por defecto); line vty 0 4: exec-timeout 10 0 (por defecto) | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | CUMPLE | banner exec configurado | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. |
| 1.3.2 | Set the 'banner-text' for 'banner login' | CUMPLE | banner login configurado | Aviso legal de acceso restringido antes de autenticarse. |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | CUMPLE | banner motd configurado | Mensaje del dia: recuerda que el equipo es de uso controlado. |
| 1.4.1 | Set 'password' for 'enable secret' | CUMPLE | enable secret presente | enable secret guarda un hash; 'enable password' queda legible en la configuracion. |
| 1.4.2 | Enable 'service password-encryption' | CUMPLE | service password-encryption activo | Cifra las claves en la configuracion para que no se lean a simple vista. |
| 1.5.2 | Unset private for 'snmp-server community' | CUMPLE | sin comunidad 'private' | 'private' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.3 | Unset public for 'snmp-server community' | CUMPLE | sin comunidad 'public' | 'public' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | CUMPLE | sin comunidades RW | Una comunidad de escritura permite modificar el equipo por SNMP. |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | CUMPLE | ip ssh time-out 60 | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. |
| 2.1.2 | Set 'no cdp run' | CUMPLE | CDP deshabilitado | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. |
| 2.1.3 | Set 'no ip bootp server' | CUMPLE | BOOTP deshabilitado | BOOTP es un servicio innecesario que amplia la superficie de ataque. |
| 2.1.8 | Set 'no service pad' | CUMPLE | service pad deshabilitado | PAD es un servicio heredado sin uso. |
| 2.2.4 | Set IP address for 'logging host' | CUMPLE | logging host 10.8.25.11 | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | CUMPLE | servidor HTTP deshabilitado | El servidor HTTP del router va en claro y amplia la superficie de ataque. |

## SW1

| ID CIS | Control | Estado | Evidencia | Por que |
|---|---|---|---|---|
| 1.2.2 | Set 'transport input ssh' for 'line vty' | CUMPLE | line vty 0 4: transport input ssh | Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion. |
| 1.2.4 | Create 'access-list' for use with 'line vty' | CUMPLE | VTY-ACL: permit 10.8.25.11 / deny   any log | Define quien puede administrar el equipo: solo la estacion ADMIN. |
| 1.2.5 | Set 'access-class' for 'line vty' | CUMPLE | line vty 0 4: access-class VTY-ACL in | Sin access-class, cualquier host de la red puede intentar entrar por vty. |
| - | Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF) | CUMPLE | line con 0: exec-timeout 10 0 (por defecto); line vty 0 4: exec-timeout 10 0 (por defecto) | Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta. |
| 1.3.1 | Set the 'banner-text' for 'banner exec' | CUMPLE | banner exec configurado | Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos. |
| 1.3.2 | Set the 'banner-text' for 'banner login' | CUMPLE | banner login configurado | Aviso legal de acceso restringido antes de autenticarse. |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | CUMPLE | banner motd configurado | Mensaje del dia: recuerda que el equipo es de uso controlado. |
| 1.4.1 | Set 'password' for 'enable secret' | CUMPLE | enable secret presente | enable secret guarda un hash; 'enable password' queda legible en la configuracion. |
| 1.4.2 | Enable 'service password-encryption' | CUMPLE | service password-encryption activo | Cifra las claves en la configuracion para que no se lean a simple vista. |
| 1.5.2 | Unset private for 'snmp-server community' | CUMPLE | sin comunidad 'private' | 'private' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.3 | Unset public for 'snmp-server community' | CUMPLE | sin comunidad 'public' | 'public' es una comunidad por defecto conocida por cualquier atacante. |
| 1.5.4 | Do not set 'RW' for any 'snmp-server community' | CUMPLE | sin comunidades RW | Una comunidad de escritura permite modificar el equipo por SNMP. |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | CUMPLE | ip ssh time-out 60 | Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta. |
| 2.1.2 | Set 'no cdp run' | CUMPLE | CDP deshabilitado | CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio. |
| 2.1.3 | Set 'no ip bootp server' | CUMPLE | BOOTP deshabilitado | BOOTP es un servicio innecesario que amplia la superficie de ataque. |
| 2.1.8 | Set 'no service pad' | CUMPLE | service pad deshabilitado | PAD es un servicio heredado sin uso. |
| 2.2.4 | Set IP address for 'logging host' | CUMPLE | logging host 10.8.25.11 | Centraliza los logs en ADMIN: la evidencia queda fuera del equipo. |
| - | Set 'no ip http server' (ID por confirmar en el PDF) | CUMPLE | servidor HTTP deshabilitado | El servidor HTTP del router va en claro y amplia la superficie de ataque. |
