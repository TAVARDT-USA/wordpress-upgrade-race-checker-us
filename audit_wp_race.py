#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT WordPress Upgrade Race Condition & RCE Auditor (CLI)
Ferramenta de auditoria de seguranca para deteccao de exposicao e execucao
em diretorios transitorios de atualizacao do WordPress (wp-content/upgrade/).
"""

import sys
import argparse
import urllib.request
import urllib.error
import ssl
import json
import time
import re
from urllib.parse import urlparse

def sanitize_target(raw_url):
    raw_url = raw_url.strip()
    if any(c in raw_url for c in ['<', '>', '"', "'", '`']) or 'javascript:' in raw_url.lower() or 'data:' in raw_url.lower():
        return None, "Entrada rejeitada: a URL contém caracteres perigosos ou sequencias de script."
    
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
        
    try:
        p = urlparse(raw_url)
        if p.scheme not in ["http", "https"]:
            return None, "Protocolo inválido. Utilize apenas http ou https."
        if not p.netloc or "." not in p.netloc:
            return None, "Hostname inválido."
        clean = f"{p.scheme}://{p.netloc}"
        return clean, "OK"
    except Exception as e:
        return None, f"Erro de parsing de URL: {e}"

def make_request(url, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TAVARDT-WordPress-Race-Auditor/1.0 (+https://ag.tavardt.com/br/ciberseguranca/)"}
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            elapsed = round((time.time() - t0) * 1000, 2)
            final_url = r.geturl()
            body = r.read(4096).decode("utf-8", errors="ignore")
            headers = dict(r.info())
            return {
                "ok": True,
                "status": r.status,
                "final_url": final_url,
                "is_redirect": final_url.rstrip("/") != url.rstrip("/"),
                "body": body,
                "headers": headers,
                "elapsed_ms": elapsed,
                "error": None
            }
    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - t0) * 1000, 2)
        try:
            body = e.read(2048).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {
            "ok": True,
            "status": e.code,
            "body": body,
            "headers": dict(e.headers),
            "elapsed_ms": elapsed,
            "error": f"HTTP {e.code}"
        }
    except Exception as ex:
        return {
            "ok": False,
            "status": 0,
            "body": "",
            "headers": {},
            "elapsed_ms": 0,
            "error": str(ex)
        }

def detect_wordpress(base_url, timeout=5):
    signals = []
    
    # 1. Checagem da home para gerador ou assets
    res_home = make_request(base_url, timeout)
    if res_home["ok"]:
        b = res_home["body"].lower()
        if "wp-content" in b or "wp-includes" in b or 'generator" content="wordpress' in b:
            signals.append("HTML Root (wp-content / wp-includes)")
            
    # 2. Checagem de /wp-json/
    res_json = make_request(base_url.rstrip("/") + "/wp-json/", timeout)
    if res_json["ok"] and res_json["status"] == 200:
        if "namespaces" in res_json["body"] or "wp/v2" in res_json["body"]:
            signals.append("REST API (/wp-json/)")
            
    # 3. Checagem de /wp-login.php
    res_login = make_request(base_url.rstrip("/") + "/wp-login.php", timeout)
    if res_login["ok"] and res_login["status"] in [200, 302]:
        if "login" in res_login["body"].lower() or "wp-submit" in res_login["body"]:
            signals.append("Login Form (/wp-login.php)")

    # 4. Checagem de asset canonico do core
    res_asset = make_request(base_url.rstrip("/") + "/wp-admin/images/wordpress-logo.svg", timeout)
    ctype = res_asset.get("headers", {}).get("Content-Type", "").lower()
    if res_asset["ok"] and res_asset["status"] == 200 and not res_asset.get("is_redirect", False):
        if "svg" in ctype or "<svg" in res_asset["body"].lower():
            signals.append("Core Asset (/wp-admin/images/wordpress-logo.svg)")

    return len(signals) > 0, signals

def check_catch_all_spa(base_url, timeout=5):
    # Proba uma rota aleatoria inexistente
    dummy_url = base_url.rstrip("/") + "/tavardt-spa-probe-784912.html"
    res = make_request(dummy_url, timeout)
    # Se uma rota inexistente responder 200 com HTML generico, o servidor e SPA / Catch-All
    if res["ok"] and res["status"] == 200:
        return True
    return False

def audit_target(raw_target, timeout=5):
    clean_url, err_msg = sanitize_target(raw_target)
    if not clean_url:
        return {
            "target": raw_target,
            "status": "REJEITADO",
            "score": 0,
            "risk_level": "ENTRADA INVÁLIDA",
            "error": err_msg,
            "findings": []
        }
        
    # 1. Teste de Acessibilidade
    res_root = make_request(clean_url, timeout)
    if not res_root["ok"]:
        return {
            "target": clean_url,
            "status": "HOST_INACESSIVEL",
            "score": 0,
            "risk_level": "FALHA DE REDE",
            "error": f"Não foi possível conectar ao host: {res_root['error']}",
            "findings": []
        }
        
    # 2. Fingerprinting de WordPress
    is_wp, wp_signals = detect_wordpress(clean_url, timeout)
    if not is_wp:
        return {
            "target": clean_url,
            "status": "NÃO_WORDPRESS",
            "score": 100,
            "risk_level": "NÃO APLICÁVEL",
            "message": "O host respondeu com sucesso, mas nenhuma assinatura do WordPress foi identificada. O teste de wp-content/upgrade nao se aplica a esta arquitetura.",
            "findings": []
        }
        
    # 3. Detecção de Roteador Catch-All / SPA
    is_catch_all = check_catch_all_spa(clean_url, timeout)
    
    # 4. Inspecao de Rotas do WordPress
    test_routes = [
        {"path": "/wp-content/upgrade/", "desc": "Diretório transitório de upgrade", "critical": True},
        {"path": "/wp-content/upgrade/test.php", "desc": "Execução de PHP transitorio", "critical": True},
        {"path": "/wp-content/uploads/", "desc": "Diretório de uploads de midia", "critical": False},
        {"path": "/wp-content/uploads/test.php", "desc": "Execução de PHP em uploads", "critical": True}
    ]
    
    findings = []
    vulnerable = False
    
    for r in test_routes:
        full_url = clean_url.rstrip("/") + r["path"]
        res = make_request(full_url, timeout)
        
        status_code = res["status"]
        is_index_of = "index of" in res["body"].lower()
        is_redir = res.get("is_redirect", False)
        
        # Se houve redirecionamento para home ou outra rota, a pasta nao esta exposta
        if is_redir and status_code == 200 and not is_index_of:
            status_text = f"HTTP 200 (Redirecionado para {res.get('final_url')[:30]}...)"
            is_vuln_route = False
        # Se for catch-all router e nao tiver index of, 200 nao significa vulnerabilidade real de pasta
        elif is_catch_all and status_code == 200 and not is_index_of:
            status_text = f"HTTP {status_code} (Catch-All SPA / Roteador)"
            is_vuln_route = False
        elif status_code == 200:
            status_text = "HTTP 200 (Aberto / Executavel)" if not is_index_of else "HTTP 200 (Directory Listing Ativo)"
            is_vuln_route = True
        elif status_code == 403:
            status_text = "HTTP 403 (Bloqueado Corretamente)"
            is_vuln_route = False
        elif status_code == 404:
            status_text = "HTTP 404 (Não Encontrado / Protegido)"
            is_vuln_route = False
        else:
            status_text = f"HTTP {status_code}"
            is_vuln_route = False
            
        if is_vuln_route and r["critical"]:
            vulnerable = True
            
        findings.append({
            "route": r["path"],
            "status": status_code,
            "status_text": status_text,
            "vulnerable": is_vuln_route,
            "elapsed_ms": res["elapsed_ms"]
        })
        
    score = 25 if vulnerable else 100
    risk_level = "CRITICO (9.8 CVSS)" if vulnerable else "MINIMO (0.0 CVSS)"
    
    return {
        "target": clean_url,
        "status": "VULNERÁVEL" if vulnerable else "BLINDADO",
        "score": score,
        "risk_level": risk_level,
        "is_wordpress": True,
        "wp_signals": wp_signals,
        "is_catch_all_spa": is_catch_all,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="TAVARDT: Auditor de Race Condition no Upgrade do WordPress & RCE")
    parser.add_argument("target", nargs="?", default=None, help="URL do alvo a ser auditado")
    parser.add_argument("-u", dest="url", default=None, help="URL do alvo a ser auditado")
    parser.add_argument("-t", dest="timeout", type=int, default=5, help="Timeout de conexao em segundos")
    parser.add_argument("-j", dest="json", action="store_true", help="Retorna o resultado em formato JSON")
    args = parser.parse_args()
    
    target_url = args.url or args.target
    if not target_url:
        print("Uso: python audit_wp_race.py https://seu-dominio.com.br")
        sys.exit(1)
        
    report = audit_target(target_url, args.timeout)
    
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return
        
    print("=" * 75)
    print("  TAVARDT - Auditoria de Segurança: Upgrade Race Condition & RCE")
    print("=" * 75)
    print(f"Alvo Analisado     : {report['target']}")
    print(f"Status Operacional : {report['status']}")
    print(f"Pontuação (Score)  : {report['score']}/100")
    print(f"Nível de Risco     : {report['risk_level']}")
    
    if report.get("error"):
        print(f"Alerta             : {report['error']}")
    elif report.get("message"):
        print(f"Diagnóstico        : {report['message']}")
        
    if report.get("findings"):
        print("-" * 75)
        print("Inspeção de Rotas Críticas:")
        for f in report["findings"]:
            tag = "[! ALERTA]" if f["vulnerable"] else "[✓ OK]"
            print(f"  {tag:<10} {f['route']:<32} -> {f['status_text']} ({f['elapsed_ms']}ms)")
            
    print("=" * 75)

if __name__ == "__main__":
    main()
