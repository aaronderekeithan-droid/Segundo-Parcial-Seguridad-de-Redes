#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening.py - Auditoria y hardening CIS de un router, un switch y un firewall
  - Cisco IOS 15 (R1, SW1): CIS Cisco IOS 15 Benchmark v4.1.1
  - FortiGate 7.0.x (FW1): CIS FortiGate Benchmark (controles de administracion, cuentas y logs)

Estudiante: Aaron Hernandez - Matricula 2025-0800 - Red 10.8.25.0/24

Modos:
  audit   Revisa R1, SW1 y FW1 y genera un informe SIN cambiar nada.
  harden  Aplica los controles que no cumplen, guarda la configuracion,
          vuelve a auditar y genera el informe final (Antes / Despues / Por que).

Ejemplos:
  python cis_hardening.py audit
  python cis_hardening.py harden
  python cis_hardening.py audit --offline R1=R1_antes.txt FW1=FW1_antes.conf
  python cis_hardening.py audit --devices R1=10.8.25.1 FW1=10.8.25.3

Salida (carpeta reports/<fecha>/):
  informe_audit.md o informe_harden.md
  running-configs/<equipo>_antes.txt y <equipo>_despues.txt
"""

import argparse
import getpass
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional

# --------------------------------------------------------------------------
# Parametros del laboratorio
# --------------------------------------------------------------------------
DEVICES = {"R1": ("10.8.25.1", "cisco"),
           "SW1": ("10.8.25.2", "cisco"),
           "FW1": ("10.8.25.3", "fortigate")}
ADMIN_IP = "10.8.25.10"      # estacion ADMIN: unica que puede administrar por vty
SYSLOG_IP = "10.8.25.10"     # servidor de logs (rsyslog en ADMIN)
ACL_NAME = "VTY-ACL"
EXEC_TIMEOUT_CMD = "exec-timeout 5 0"

OK, FAIL, NA = "CUMPLE", "NO CUMPLE", "N/A"
SKIP_IDS = set()   # IDs de controles que no se auditan ni se aplican (opcion --skip)

BANNERS = {
    "exec": "Sesion autorizada. Toda la actividad queda registrada.",
    "login": "ACCESO RESTRINGIDO. Solo personal autorizado. "
             "Toda la actividad es registrada y monitoreada.",
    "motd": "Equipo del laboratorio de Seguridad de Redes - ITLA.",
}


@dataclass
class Ctx:
    admin_ip: str = ADMIN_IP
    syslog_ip: str = SYSLOG_IP
    new_secret: Optional[str] = None


@dataclass
class Check:
    cid: str            # ID del CIS Benchmark ("" si no esta verificado)
    title: str
    why: str
    test: Callable      # (cfg, ctx) -> (bool, evidencia)
    fix: Callable       # (cfg, ctx) -> lista de comandos


# --------------------------------------------------------------------------
# Utilidades para leer la running-config
# --------------------------------------------------------------------------
def has(cfg: str, pattern: str) -> bool:
    return re.search(pattern, cfg, re.M) is not None


def line_blocks(cfg: str, prefix: str):
    """Devuelve [(encabezado, [lineas hijas])] de los bloques que empiezan con prefix."""
    blocks, cur = [], None
    for raw in cfg.splitlines():
        if raw.startswith(prefix):
            cur = (raw.strip(), [])
            blocks.append(cur)
        elif cur is not None and raw[:1] in (" ", "\t"):
            cur[1].append(raw.strip())
        else:
            cur = None
    return blocks


def snmp_lines(cfg: str):
    return [l.split() for l in cfg.splitlines() if l.startswith("snmp-server community ")]


# --------------------------------------------------------------------------
# Pruebas (test) y correcciones (fix) de cada control
# --------------------------------------------------------------------------
def t_transport_ssh(cfg, ctx):
    blocks = line_blocks(cfg, "line vty")
    if not blocks:
        return False, "sin lineas vty en la configuracion"
    ok, ev = True, []
    for hdr, body in blocks:
        tr = [l for l in body if l.startswith("transport input")]
        val = tr[0] if tr else "transport input all (por defecto)"
        ev.append(f"{hdr}: {val}")
        if val != "transport input ssh":
            ok = False
    return ok, "; ".join(ev)


def f_transport_ssh(cfg, ctx):
    cmds = []
    for hdr, _ in line_blocks(cfg, "line vty"):
        cmds += [hdr, "transport input ssh", "exit"]
    return cmds


def t_vty_acl(cfg, ctx):
    m = re.search(rf"^ip access-list standard {ACL_NAME}\n((?: .*\n?)*)", cfg, re.M)
    if not m:
        return False, f"no existe la ACL {ACL_NAME}"
    body = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    if not any(ctx.admin_ip in l and l.startswith("permit") for l in body):
        return False, f"la ACL {ACL_NAME} no permite a {ctx.admin_ip}: " + " | ".join(body)
    return True, f"{ACL_NAME}: " + " | ".join(body)


def f_vty_acl(cfg, ctx):
    return [f"ip access-list standard {ACL_NAME}",
            f"permit host {ctx.admin_ip}",
            "deny any log",
            "exit"]


def t_access_class(cfg, ctx):
    blocks = line_blocks(cfg, "line vty")
    if not blocks:
        return False, "sin lineas vty en la configuracion"
    ok, ev = True, []
    for hdr, body in blocks:
        ac = next((l for l in body if l.startswith("access-class")), None)
        ev.append(f"{hdr}: {ac or 'sin access-class'}")
        if not (ac and ac.startswith(f"access-class {ACL_NAME} in")):
            ok = False
    return ok, "; ".join(ev)


def f_access_class(cfg, ctx):
    cmds = []
    for hdr, _ in line_blocks(cfg, "line vty"):
        cmds += [hdr, f"access-class {ACL_NAME} in", "exit"]
    return cmds


def _timeout_seconds(line):
    m = re.match(r"exec-timeout (\d+)(?: (\d+))?$", line)
    return int(m.group(1)) * 60 + int(m.group(2) or 0) if m else None


def _bad_timeout_headers(cfg):
    bad, ev = [], []
    for prefix in ("line con", "line vty"):
        for hdr, body in line_blocks(cfg, prefix):
            val = next((l for l in body if l.startswith("exec-timeout")), None)
            secs = _timeout_seconds(val) if val else 600
            ev.append(f"{hdr}: {val or 'exec-timeout 10 0 (por defecto)'}")
            if secs == 0 or secs is None or secs > 600:
                bad.append(hdr)
    return bad, ev


def t_exec_timeout(cfg, ctx):
    bad, ev = _bad_timeout_headers(cfg)
    if not ev:
        return False, "sin lineas con/vty en la configuracion"
    return (not bad), "; ".join(ev)


def f_exec_timeout(cfg, ctx):
    cmds = []
    for hdr in _bad_timeout_headers(cfg)[0]:
        cmds += [hdr, EXEC_TIMEOUT_CMD, "exit"]
    return cmds


def t_banner(kind):
    def _t(cfg, ctx):
        ok = has(cfg, rf"^banner {kind}\b")
        return ok, (f"banner {kind} configurado" if ok else f"sin banner {kind}")
    return _t


def f_banner(kind):
    return lambda cfg, ctx: [f"banner {kind} # {BANNERS[kind]} #"]


def t_secret(cfg, ctx):
    sec = has(cfg, r"^enable secret ")
    pwd = has(cfg, r"^enable password ")
    ev = "enable secret presente" if sec else "sin enable secret"
    if pwd:
        ev += "; enable password en uso"
    return (sec and not pwd), ev


def f_secret(cfg, ctx):
    if not ctx.new_secret:
        return []
    cmds = [f"enable secret {ctx.new_secret}"]
    if has(cfg, r"^enable password "):
        cmds.append("no enable password")
    return cmds


def t_pwd_encryption(cfg, ctx):
    ok = has(cfg, r"^service password-encryption")
    return ok, ("service password-encryption activo" if ok else "no service password-encryption")


def t_snmp_name(name):
    def _t(cfg, ctx):
        found = [p for p in snmp_lines(cfg) if len(p) > 2 and p[2] == name]
        return (not found), (f"comunidad '{name}' presente" if found else f"sin comunidad '{name}'")
    return _t


def f_snmp_name(name):
    return lambda cfg, ctx: [f"no snmp-server community {name}"]


def _rw_communities(cfg):
    return [p[2] for p in snmp_lines(cfg)
            if len(p) > 2 and any(x.upper() == "RW" for x in p[3:])]


def t_snmp_rw(cfg, ctx):
    rw = _rw_communities(cfg)
    return (not rw), (f"comunidades RW: {', '.join(rw)}" if rw else "sin comunidades RW")


def f_snmp_rw(cfg, ctx):
    return [f"no snmp-server community {n}" for n in _rw_communities(cfg)
            if n not in ("private", "public")]


def t_ssh_timeout(cfg, ctx):
    m = re.search(r"^ip ssh time-out (\d+)", cfg, re.M)
    if not m:
        return False, "ip ssh time-out no configurado (por defecto 120 s)"
    v = int(m.group(1))
    return v <= 60, f"ip ssh time-out {v}"


def t_no_cmd(pattern, on_msg, off_msg):
    def _t(cfg, ctx):
        ok = has(cfg, pattern)
        return ok, (off_msg if ok else on_msg)
    return _t


def f_cmds(*cmds):
    return lambda cfg, ctx: list(cmds)


def t_logging(cfg, ctx):
    ip = re.escape(ctx.syslog_ip)
    ok = has(cfg, rf"^logging (host )?{ip}\b")
    return ok, (f"logging host {ctx.syslog_ip}" if ok else "sin servidor de logs remoto")


def f_logging(cfg, ctx):
    return [f"logging host {ctx.syslog_ip}"]


def t_http(cfg, ctx):
    on = [l for l in ("ip http server", "ip http secure-server") if has(cfg, rf"^{l}\s*$")]
    return (not on), (f"activo: {', '.join(on)}" if on else "servidor HTTP deshabilitado")


def f_http(cfg, ctx):
    return ["no " + l for l in ("ip http server", "ip http secure-server")
            if has(cfg, rf"^{l}\s*$")]


# --------------------------------------------------------------------------
# Lista de controles (IDs verificados en la auditoria de ONYX, CIS IOS 15 v4.1.1)
# --------------------------------------------------------------------------
CISCO_CHECKS: List[Check] = [
    Check("1.2.2", "Set 'transport input ssh' for 'line vty'",
          "Telnet envia usuario y clave en texto plano; solo SSH cifra la sesion de administracion.",
          t_transport_ssh, f_transport_ssh),
    Check("1.2.4", "Create 'access-list' for use with 'line vty'",
          "Define quien puede administrar el equipo: solo la estacion ADMIN.",
          t_vty_acl, f_vty_acl),
    Check("1.2.5", "Set 'access-class' for 'line vty'",
          "Sin access-class, cualquier host de la red puede intentar entrar por vty.",
          t_access_class, f_access_class),
    Check("", "Set 'exec-timeout' <= 10 min en 'line con 0' y 'line vty' (ID por confirmar en el PDF)",
          "Cierra sesiones abandonadas; una sesion privilegiada olvidada es una puerta abierta.",
          t_exec_timeout, f_exec_timeout),
    Check("1.3.1", "Set the 'banner-text' for 'banner exec'",
          "Aviso de uso autorizado al abrir una sesion EXEC; sirve como respaldo ante accesos indebidos.",
          t_banner("exec"), f_banner("exec")),
    Check("1.3.2", "Set the 'banner-text' for 'banner login'",
          "Aviso legal de acceso restringido antes de autenticarse.",
          t_banner("login"), f_banner("login")),
    Check("1.3.3", "Set the 'banner-text' for 'banner motd'",
          "Mensaje del dia: recuerda que el equipo es de uso controlado.",
          t_banner("motd"), f_banner("motd")),
    Check("1.4.1", "Set 'password' for 'enable secret'",
          "enable secret guarda un hash; 'enable password' queda legible en la configuracion.",
          t_secret, f_secret),
    Check("1.4.2", "Enable 'service password-encryption'",
          "Cifra las claves en la configuracion para que no se lean a simple vista.",
          t_pwd_encryption, f_cmds("service password-encryption")),
    Check("1.5.2", "Unset private for 'snmp-server community'",
          "'private' es una comunidad por defecto conocida por cualquier atacante.",
          t_snmp_name("private"), f_snmp_name("private")),
    Check("1.5.3", "Unset public for 'snmp-server community'",
          "'public' es una comunidad por defecto conocida por cualquier atacante.",
          t_snmp_name("public"), f_snmp_name("public")),
    Check("1.5.4", "Do not set 'RW' for any 'snmp-server community'",
          "Una comunidad de escritura permite modificar el equipo por SNMP.",
          t_snmp_rw, f_snmp_rw),
    Check("2.1.1.1.4", "Set 'seconds' for 'ip ssh timeout'",
          "Limita el tiempo para autenticarse por SSH y reduce conexiones colgadas y fuerza bruta.",
          t_ssh_timeout, f_cmds("ip ssh time-out 60")),
    Check("2.1.2", "Set 'no cdp run'",
          "CDP revela modelo, version e IP a cualquier vecino; no se usa en este laboratorio.",
          t_no_cmd(r"^no cdp run", "CDP activo", "CDP deshabilitado"), f_cmds("no cdp run")),
    Check("2.1.3", "Set 'no ip bootp server'",
          "BOOTP es un servicio innecesario que amplia la superficie de ataque.",
          t_no_cmd(r"^no ip bootp server", "ip bootp server activo", "BOOTP deshabilitado"),
          f_cmds("no ip bootp server")),
    Check("2.1.4", "Set 'no service dhcp'",
          "El equipo no es servidor DHCP en esta topologia; el servicio se apaga.",
          t_no_cmd(r"^no service dhcp", "service dhcp activo", "service dhcp deshabilitado"),
          f_cmds("no service dhcp")),
    Check("2.1.8", "Set 'no service pad'",
          "PAD es un servicio heredado sin uso.",
          t_no_cmd(r"^no service pad", "service pad activo", "service pad deshabilitado"),
          f_cmds("no service pad")),
    Check("2.2.4", "Set IP address for 'logging host'",
          "Centraliza los logs en ADMIN: la evidencia queda fuera del equipo.",
          t_logging, f_logging),
    Check("", "Set 'no ip http server' (ID por confirmar en el PDF)",
          "El servidor HTTP del router va en claro y amplia la superficie de ataque.",
          t_http, f_http),
]


# --------------------------------------------------------------------------
# FortiGate: lectura de la configuracion ("show full-configuration")
# --------------------------------------------------------------------------
def fg_block(cfg: str, header: str):
    """Lineas (sin indentar) del bloque 'config <header>' de nivel 0, sin su 'end'."""
    out, inside, depth = [], False, 0
    for ln in cfg.splitlines():
        if not inside:
            if ln.rstrip() == f"config {header}":
                inside, depth = True, 1
            continue
        s = ln.strip()
        if s.startswith("config "):
            depth += 1
        elif s == "end":
            depth -= 1
            if depth == 0:
                break
        out.append(s)
    return out


def fg_settings(block):
    """Lineas 'set clave valor' del primer nivel de un bloque sin 'edit'."""
    d, depth = {}, 0
    for s in block:
        if s.startswith("config "):
            depth += 1
            continue
        if s == "end" and depth > 0:
            depth -= 1
            continue
        if depth > 0:
            continue
        m = re.match(r"set (\S+) (.*)$", s)
        if m:
            d[m.group(1)] = m.group(2).strip().strip('"')
    return d


def fg_entries(block):
    """Entradas 'edit nombre ... next' del primer nivel, ignorando bloques anidados."""
    entries, cur, depth = {}, None, 0
    for s in block:
        if s.startswith("config "):
            depth += 1
            continue
        if s == "end" and depth > 0:
            depth -= 1
            continue
        if depth > 0:
            continue
        m = re.match(r'edit (?:"([^"]+)"|(\S+))$', s)
        if m:
            cur = m.group(1) or m.group(2)
            entries[cur] = {}
            continue
        if s == "next":
            cur = None
            continue
        m = re.match(r"set (\S+) (.*)$", s)
        if m and cur is not None:
            entries[cur][m.group(1)] = m.group(2).strip().strip('"')
    return entries


# --------------------------------------------------------------------------
# FortiGate: pruebas y correcciones
# --------------------------------------------------------------------------
def t_fg_mgmt(cfg, ctx):
    ent = fg_entries(fg_block(cfg, "system interface"))
    if not ent:
        return False, "no pude leer las interfaces de la configuracion"
    bad, ev = [], []
    for name, kv in ent.items():
        acc = kv.get("allowaccess", "").split()
        if acc:
            ev.append(f"{name}: {' '.join(acc)}")
        if {"http", "telnet"} & set(acc):
            bad.append(name)
    return (not bad), ("; ".join(ev) or "ninguna interfaz con acceso administrativo")


def f_fg_mgmt(cfg, ctx):
    cmds = []
    for name, kv in fg_entries(fg_block(cfg, "system interface")).items():
        acc = kv.get("allowaccess", "").split()
        if {"http", "telnet"} & set(acc):
            keep = [a for a in acc if a not in ("http", "telnet")]
            cmds += ["config system interface", f'edit "{name}"',
                     f"set allowaccess {' '.join(keep)}" if keep else "unset allowaccess",
                     "next", "end"]
    return cmds


def t_fg_timeout(cfg, ctx):
    g = fg_settings(fg_block(cfg, "system global"))
    try:
        v = int(g.get("admintimeout", "5"))
    except ValueError:
        return False, f"admintimeout con valor raro: {g.get('admintimeout')}"
    return v <= 5, f"admintimeout {v} min"


def f_fg_timeout(cfg, ctx):
    return ["config system global", "set admintimeout 5", "end"]


_PWD_MIN = {"minimum-length": 8, "min-lower-case-letter": 1, "min-upper-case-letter": 1,
            "min-number": 1, "min-non-alphanumeric": 1}


def t_fg_password(cfg, ctx):
    p = fg_settings(fg_block(cfg, "system password-policy"))
    status = p.get("status", "disable")
    low = []
    for k, need in _PWD_MIN.items():
        try:
            val = int(p.get(k, "8" if k == "minimum-length" else "0"))
        except ValueError:
            val = 0
        if val < need:
            low.append(f"{k}={val}")
    ev = f"password-policy status {status}"
    if low:
        ev += "; por debajo del minimo: " + ", ".join(low)
    return (status == "enable" and not low), ev


def f_fg_password(cfg, ctx):
    return (["config system password-policy", "set status enable"]
            + [f"set {k} {v}" for k, v in _PWD_MIN.items()] + ["end"])


def t_fg_trusthost(cfg, ctx):
    ent = fg_entries(fg_block(cfg, "system admin"))
    if not ent:
        return False, "no pude leer los administradores"
    bad, ev = [], []
    for name, kv in ent.items():
        th = kv.get("trusthost1", "0.0.0.0 0.0.0.0")
        ev.append(f"{name}: trusthost1 {th}")
        if th.startswith("0.0.0.0") or ctx.admin_ip not in th:
            bad.append(name)
    return (not bad), "; ".join(ev)


def f_fg_trusthost(cfg, ctx):
    cmds = []
    for name, kv in fg_entries(fg_block(cfg, "system admin")).items():
        th = kv.get("trusthost1", "0.0.0.0 0.0.0.0")
        if th.startswith("0.0.0.0") or ctx.admin_ip not in th:
            cmds += ["config system admin", f'edit "{name}"',
                     f"set trusthost1 {ctx.admin_ip} 255.255.255.255", "next", "end"]
    return cmds


def t_fg_syslog(cfg, ctx):
    s = fg_settings(fg_block(cfg, "log syslogd setting"))
    ok = s.get("status") == "enable" and s.get("server") == ctx.syslog_ip
    return ok, (f"syslogd {s.get('status', 'disable')}, servidor {s.get('server', '-')}")


def f_fg_syslog(cfg, ctx):
    return ["config log syslogd setting", "set status enable",
            f"set server {ctx.syslog_ip}", "end"]


def t_fg_autoinstall(cfg, ctx):
    a = fg_settings(fg_block(cfg, "system auto-install"))
    cfg_on = a.get("auto-install-config", "enable") == "enable"
    img_on = a.get("auto-install-image", "enable") == "enable"
    return (not cfg_on and not img_on), (
        f"auto-install-config {'enable' if cfg_on else 'disable'}, "
        f"auto-install-image {'enable' if img_on else 'disable'}")


def f_fg_autoinstall(cfg, ctx):
    return ["config system auto-install", "set auto-install-config disable",
            "set auto-install-image disable", "end"]


def t_fg_tls(cfg, ctx):
    g = fg_settings(fg_block(cfg, "system global"))
    versions = g.get("admin-https-ssl-versions")
    if versions is None:
        return True, "admin-https-ssl-versions por defecto (sin TLS 1.0/1.1 explicito)"
    weak = [v for v in versions.split() if v in ("tlsv1-0", "tlsv1-1")]
    return (not weak), f"admin-https-ssl-versions {versions}"


def f_fg_tls(cfg, ctx):
    return ["config system global", "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"]


# IDs del CIS FortiGate: se completan con los que reporta el verificador (ver README)
FG_IDS = {}

FG_CHECKS: List[Check] = [
    Check(FG_IDS.get("mgmt", ""), "Disable insecure management protocols (HTTP, Telnet) on interfaces",
          "HTTP y Telnet administran el firewall en texto plano; solo HTTPS y SSH cifran la sesion.",
          t_fg_mgmt, f_fg_mgmt),
    Check(FG_IDS.get("timeout", ""), "Set 'admintimeout' to 5 minutes or less",
          "Cierra sesiones de administracion abandonadas.",
          t_fg_timeout, f_fg_timeout),
    Check(FG_IDS.get("password", ""), "Enable password policy (length 8, upper, lower, number, special)",
          "Evita claves de administrador debiles.",
          t_fg_password, f_fg_password),
    Check(FG_IDS.get("trusthost", ""), "Restrict administrator access with 'trusthost'",
          "Solo la estacion ADMIN puede iniciar sesion como administrador.",
          t_fg_trusthost, f_fg_trusthost),
    Check(FG_IDS.get("syslog", ""), "Enable remote logging to a syslog server",
          "Los logs quedan en ADMIN, fuera del equipo, como evidencia.",
          t_fg_syslog, f_fg_syslog),
    Check(FG_IDS.get("autoinstall", ""), "Disable USB auto-install of configuration and firmware",
          "Evita que alguien con acceso fisico cargue configuracion o firmware desde un USB.",
          t_fg_autoinstall, f_fg_autoinstall),
    Check(FG_IDS.get("tls", ""), "Disable TLS 1.0/1.1 for the HTTPS administrative interface",
          "Las versiones TLS antiguas tienen debilidades conocidas.",
          t_fg_tls, f_fg_tls),
]

CHECKS_BY_PLATFORM = {"cisco": CISCO_CHECKS, "fortigate": FG_CHECKS}


# --------------------------------------------------------------------------
# Auditoria
# --------------------------------------------------------------------------
def run_checks(cfg: str, ctx: Ctx, platform: str = "cisco"):
    out = []
    for ch in CHECKS_BY_PLATFORM[platform]:
        if ch.cid and ch.cid in SKIP_IDS:
            continue
        try:
            ok, ev = ch.test(cfg, ctx)
        except Exception as exc:  # una falla de lectura no debe tumbar el informe
            ok, ev = False, f"error evaluando: {exc}"
        out.append({"check": ch, "status": OK if ok else FAIL, "ev": ev})
    return out


def score(res):
    valid = [r for r in res if r["status"] != NA]
    ok = sum(1 for r in valid if r["status"] == OK)
    return ok, len(valid)


def pct(res):
    ok, tot = score(res)
    return (100 * ok // tot) if tot else 100


# --------------------------------------------------------------------------
# Conexion y aplicacion (Netmiko)
# --------------------------------------------------------------------------
ERR = re.compile(r"^% (Invalid|Incomplete|Ambiguous|Unrecognized)"
                 r"|command parse error|Unknown action|value parse error"
                 r"|object set operator error|node_check_object fail", re.M)


def connect(name, ip, user, password, secret, platform="cisco"):
    from netmiko import ConnectHandler  # import tardio: audit --offline no lo necesita
    params = dict(device_type="fortinet" if platform == "fortigate" else "cisco_ios",
                  host=ip, username=user, password=password, conn_timeout=20,
                  auth_timeout=30, banner_timeout=30, global_delay_factor=2)
    if platform == "cisco":
        params["secret"] = secret
    conn = ConnectHandler(**params)
    if platform == "cisco":
        conn.enable()
    return conn


def get_config(conn, platform="cisco") -> str:
    if platform == "fortigate":
        return conn.send_command("show full-configuration", read_timeout=180)
    return conn.send_command("show running-config", read_timeout=90)


def apply_cmds(conn, cmds):
    try:
        out = conn.send_config_set(cmds, cmd_verify=False, read_timeout=60)
    except TypeError:
        out = conn.send_config_set(cmds)
    return out, bool(ERR.search(out))


def save_config(conn, platform="cisco"):
    if platform == "fortigate":
        return  # FortiOS guarda cada cambio al cerrar el bloque con 'end'
    try:
        conn.save_config()
    except Exception:
        conn.send_command_timing("write memory")


# --------------------------------------------------------------------------
# Informes
# --------------------------------------------------------------------------
def cid(ch):
    return ch.cid or "-"


def esc(s, n=150):
    s = s.replace("|", "/").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def report_audit(path, ts, results):
    L = [f"# Informe de auditoria CIS (modo audit, sin cambios)", "",
         f"- Fecha: {ts}", "- Benchmark: CIS Cisco IOS 15 v4.1.1 (R1, SW1) y CIS FortiGate (FW1)",
         "- Estudiante: Aaron Hernandez (2025-0800)", "",
         "## Resumen", "", "| Equipo | Cumple | Total | % |", "|---|---|---|---|"]
    for name, res in results.items():
        ok, tot = score(res)
        L.append(f"| {name} | {ok} | {tot} | {pct(res)} % |")
    for name, res in results.items():
        L += ["", f"## {name}", "",
              "| ID CIS | Control | Estado | Evidencia | Por que |", "|---|---|---|---|---|"]
        for r in res:
            ch = r["check"]
            L.append(f"| {cid(ch)} | {esc(ch.title, 90)} | {r['status']} | {esc(r['ev'])} | {esc(ch.why, 120)} |")
    write(path, "\n".join(L) + "\n")


def report_harden(path, ts, before, after, notes):
    L = [f"# Informe de hardening CIS (modo harden)", "",
         f"- Fecha: {ts}", "- Benchmark: CIS Cisco IOS 15 v4.1.1 (R1, SW1) y CIS FortiGate (FW1)",
         "- Estudiante: Aaron Hernandez (2025-0800)", "",
         "## Resumen", "", "| Equipo | Antes | Despues |", "|---|---|---|"]
    for name in before:
        b_ok, b_t = score(before[name])
        a_ok, a_t = score(after[name])
        L.append(f"| {name} | {b_ok}/{b_t} ({pct(before[name])} %) | {a_ok}/{a_t} ({pct(after[name])} %) |")
    for name in before:
        L += ["", f"## {name}", "",
              "| ID CIS | Control | Antes | Despues | Por que | Evidencia (despues) |",
              "|---|---|---|---|---|---|"]
        for rb, ra in zip(before[name], after[name]):
            ch = rb["check"]
            L.append(f"| {cid(ch)} | {esc(ch.title, 90)} | {rb['status']} | {ra['status']} | "
                     f"{esc(ch.why, 120)} | {esc(ra['ev'])} |")
        if notes.get(name):
            L += ["", "Observaciones:", ""] + [f"- {n}" for n in notes[name]]
    L += ["", "N/A = el equipo no soporta el comando; no cuenta para el porcentaje."]
    write(path, "\n".join(L) + "\n")


def print_summary(title, results):
    print(f"\n{title}")
    for name, res in results.items():
        ok, tot = score(res)
        print(f"  {name}: {ok}/{tot} controles cumplen ({pct(res)} %)")
        for r in res:
            if r["status"] == FAIL:
                print(f"     NO CUMPLE {cid(r['check']):>9}  {r['check'].title}")


# --------------------------------------------------------------------------
# Flujo principal
# --------------------------------------------------------------------------
def default_platform(name):
    return "fortigate" if name.upper().startswith("FW") else "cisco"


def detect_platform(cfg):
    return "fortigate" if re.search(r"^config system global\s*$", cfg, re.M) else "cisco"


def ask(prompt, env):
    return os.environ.get(env) or getpass.getpass(prompt)


def read_new_secret():
    env = os.environ.get("CIS_NEW_SECRET")
    if env:
        return env
    while True:
        s1 = getpass.getpass("Nuevo enable secret (minimo 8 caracteres): ")
        s2 = getpass.getpass("Repite el enable secret: ")
        if s1 != s2:
            print("No coinciden, intenta de nuevo.")
        elif len(s1) < 8:
            print("Demasiado corto.")
        else:
            return s1


def main():
    ap = argparse.ArgumentParser(description="Auditoria y hardening CIS para R1, SW1 y FW1")
    ap.add_argument("mode", choices=["audit", "harden"])
    ap.add_argument("--devices", nargs="+", metavar="NOMBRE=IP[,plataforma]",
                    help="por defecto R1=10.8.25.1 SW1=10.8.25.2 FW1=10.8.25.3 "
                         "(plataforma: cisco o fortigate; los nombres FW* son FortiGate)")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--admin-ip", default=ADMIN_IP, help="IP de la estacion ADMIN (ACL vty en Cisco, trusthost en FortiGate)")
    ap.add_argument("--syslog", default=SYSLOG_IP, help="IP del servidor de logs")
    ap.add_argument("--offline", nargs="+", metavar="NOMBRE=ARCHIVO",
                    help="audita configuraciones guardadas (solo modo audit)")
    ap.add_argument("--skip", nargs="+", default=[], metavar="ID",
                    help="IDs CIS a omitir, por ejemplo --skip 2.1.4 (conserva el servidor DHCP)")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--yes", action="store_true", help="no pedir confirmacion (harden)")
    args = ap.parse_args()

    SKIP_IDS.update(args.skip)
    ctx = Ctx(admin_ip=args.admin_ip, syslog_ip=args.syslog)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base = os.path.join(args.out, ts)
    cfg_dir = os.path.join(base, "running-configs")

    # ---- modo offline ----
    if args.offline:
        if args.mode != "audit":
            sys.exit("--offline solo funciona con el modo audit.")
        results = {}
        for item in args.offline:
            name, _, path = item.partition("=")
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            results[name] = run_checks(text, ctx, detect_platform(text))
        report_audit(os.path.join(base, "informe_audit.md"), ts, results)
        print_summary("Resultado de la auditoria offline:", results)
        print(f"\nInforme: {os.path.join(base, 'informe_audit.md')}")
        return

    devices = dict(DEVICES)
    if args.devices:
        devices = {}
        for d in args.devices:
            name, _, rest = d.partition("=")
            ip, _, plat = rest.partition(",")
            devices[name] = (ip, plat or default_platform(name))

    password = ask(f"Clave de '{args.user}': ", "CIS_PASS")
    enable = ""
    if any(p == "cisco" for _, p in devices.values()):
        enable = ask("Enable actual de los equipos Cisco: ", "CIS_ENABLE")

    conns, cfgs_before, before, platforms = {}, {}, {}, {}
    for name, (ip, plat) in devices.items():
        print(f"Conectando a {name} ({ip}, {plat})...")
        try:
            conns[name] = connect(name, ip, args.user, password, enable, plat)
        except Exception as exc:
            print(f"  No pude conectar a {name}: {exc}")
            continue
        platforms[name] = plat
        cfgs_before[name] = get_config(conns[name], plat)
        before[name] = run_checks(cfgs_before[name], ctx, plat)
        ext = "conf" if plat == "fortigate" else "txt"
        write(os.path.join(cfg_dir, f"{name}_antes.{ext}"), cfgs_before[name])

    if not before:
        sys.exit("No se pudo auditar ningun equipo.")

    # ---- audit ----
    if args.mode == "audit":
        report_audit(os.path.join(base, "informe_audit.md"), ts, before)
        print_summary("Resultado de la auditoria (no se cambio nada):", before)
        print(f"\nInforme: {os.path.join(base, 'informe_audit.md')}")
        for c in conns.values():
            c.disconnect()
        return

    # ---- harden ----
    pending = {n: [r for r in res if r["status"] == FAIL] for n, res in before.items()}
    if not any(pending.values()):
        print_summary("Estado actual:", before)
        print("\nNada que aplicar: todos los controles ya cumplen.")
        after = before
        report_harden(os.path.join(base, "informe_harden.md"), ts, before, after, {})
        for n, c in conns.items():
            ext = "conf" if platforms[n] == "fortigate" else "txt"
            write(os.path.join(cfg_dir, f"{n}_despues.{ext}"), cfgs_before[n])
            c.disconnect()
        return

    print("\nSe aplicaran estos controles:")
    for n, items in pending.items():
        for r in items:
            print(f"  {n}: {cid(r['check']):>9}  {r['check'].title}")
    if not args.yes and input("\nEscribe SI para continuar: ").strip() != "SI":
        sys.exit("Cancelado. No se cambio nada.")

    if any(r["check"].title.startswith("Set 'password' for 'enable secret'")
           for items in pending.values() for r in items):
        ctx.new_secret = read_new_secret()

    after, notes = {}, {}
    for name, conn in conns.items():
        errors = {}
        notes[name] = []
        for r in pending[name]:
            ch = r["check"]
            cmds = ch.fix(cfgs_before[name], ctx)
            if not cmds:
                continue
            try:
                out, bad = apply_cmds(conn, cmds)
            except Exception as exc:
                notes[name].append(f"{cid(ch)}: error aplicando ({exc})")
                continue
            if bad:
                errors[ch.title] = out
                notes[name].append(f"{cid(ch)} {ch.title}: el equipo rechazo el comando")
        plat = platforms[name]
        save_config(conn, plat)
        cfg_after = get_config(conn, plat)
        ext = "conf" if plat == "fortigate" else "txt"
        write(os.path.join(cfg_dir, f"{name}_despues.{ext}"), cfg_after)
        res = run_checks(cfg_after, ctx, plat)
        for r in res:
            if r["status"] == FAIL and r["check"].title in errors:
                r["status"] = NA
                r["ev"] += " (comando no soportado en este equipo)"
        after[name] = res
        conn.disconnect()

    report_harden(os.path.join(base, "informe_harden.md"), ts,
                  {n: before[n] for n in after}, after, notes)
    print_summary("Resultado despues del hardening:", after)
    print(f"\nInforme: {os.path.join(base, 'informe_harden.md')}")
    print(f"Running-configs antes/despues: {cfg_dir}")
    if ctx.new_secret:
        print("Anota el enable secret nuevo de los equipos Cisco: el anterior ya no sirve.")


if __name__ == "__main__":
    main()
