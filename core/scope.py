"""Validação central de destino — usada pelo core Python E pelos módulos Lua.

Nenhum request sai sem passar por check_url + redirect manual via guarded().
Política: http/https, sem credencial embutida, sem IP interno
(exceto loopback em modo lab), redirects seguidos até 3 hops com revalidação,
auth nunca atravessa para outro host.
"""
import ipaddress
import socket
from urllib.parse import urlparse

import requests

MAX_REDIRECTS = 3
MAX_BODY = 200000


def _unwrap(ip):
    """IPv4 mapeado em IPv6 (::ffff:10.0.0.1) conta como IPv4."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def resolve_host(host):
    """Todos os A/AAAA; falha de DNS = bloqueado (fail-closed)."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    except Exception:
        return []
    out = []
    for fam, _, _, _, sockaddr in infos:
        try:
            out.append(_unwrap(ipaddress.ip_address(sockaddr[0])))
        except Exception:
            continue
    return out


def check_url(url, lab_mode=False):
    """(ok, motivo). Chamado a cada request E a cada redirect (anti DNS-TOCTOU)."""
    try:
        p = urlparse(url)
    except Exception:
        return False, "URL inválida"
    if p.scheme not in ("http", "https"):
        return False, f"scheme bloqueado: {p.scheme or '?'}"
    if "@" in (p.netloc or ""):
        return False, "credencial embutida na URL"
    host = p.hostname or ""
    if not host:
        return False, "sem host"
    ips = resolve_host(host)
    if not ips:
        return False, f"DNS falhou: {host}"
    for ip in ips:
        if ip.is_loopback:
            if not lab_mode:
                return False, f"loopback bloqueado: {ip}"
            continue
        if (ip.is_private or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False, f"destino interno bloqueado: {ip}"
    return True, "ok"


def _strip_auth(headers):
    return {k: v for k, v in (headers or {}).items()
            if k.lower() not in ("authorization", "apikey", "cookie", "set-cookie")}


def guarded(method, url, headers=None, params=None, body=None, timeout=10,
            lab_mode=False):
    """Request sem redirect cego. Retorna (response|None, info)."""
    headers = dict(headers or {})
    seen = 0
    cur_host = (urlparse(url).hostname or "").lower()
    while True:
        ok, reason = check_url(url, lab_mode)
        if not ok:
            return None, {"blocked": reason, "url": url}
        try:
            r = requests.request(method, url, headers=headers, params=params,
                                 json=body if body is not None else None,
                                 timeout=timeout, allow_redirects=False)
        except Exception as e:
            return None, {"error": str(e)[:150], "url": url}
        if r.status_code not in (301, 302, 303, 307, 308) or seen >= MAX_REDIRECTS:
            if r.status_code in (301, 302, 303, 307, 308):
                return None, {"blocked": "redirects demais", "url": url}
            return r, {"redirects": seen}
        loc = r.headers.get("Location", "")
        from urllib.parse import urljoin
        nxt = urljoin(url, loc)
        if (urlparse(nxt).hostname or "").lower() != cur_host:
            headers = _strip_auth(headers)  # auth nunca atravessa host
        url, seen = nxt, seen + 1
        if method not in ("GET", "HEAD") and r.status_code in (301, 302, 303):
            method, body = "GET", None


def guarded_stream(url, headers=None, timeout=10, cap=2000000, lab_mode=False):
    """Como guarded(), mas baixa o corpo em stream até cap (p/ bundles)."""
    headers = dict(headers or {})
    seen = 0
    cur_host = (urlparse(url).hostname or "").lower()
    while True:
        ok, reason = check_url(url, lab_mode)
        if not ok:
            return None, {"blocked": reason, "url": url}
        try:
            with requests.get(url, headers=headers, timeout=timeout,
                              stream=True, allow_redirects=False) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    if seen >= MAX_REDIRECTS:
                        return None, {"blocked": "redirects demais", "url": url}
                    from urllib.parse import urljoin
                    nxt = urljoin(url, r.headers.get("Location", ""))
                    if (urlparse(nxt).hostname or "").lower() != cur_host:
                        headers = _strip_auth(headers)
                    url, seen = nxt, seen + 1
                    continue
                partes, total = [], 0
                for c in r.iter_content(chunk_size=65536):
                    if not c:
                        continue
                    total += len(c)
                    if total > cap:
                        partes.append(c[:cap - (total - len(c))])
                        break
                    partes.append(c)
                return b"".join(partes).decode("utf-8", errors="replace"), {"redirects": seen}
        except Exception as e:
            return None, {"error": str(e)[:150], "url": url}
