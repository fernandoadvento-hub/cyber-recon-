import os
import sys
import ssl
import json
import socket
import argparse
import subprocess
import shutil
from datetime import datetime

# Validação e importação de dependências externas
try:
    import requests
    import dns.resolver
    import whois
except ModuleNotFoundError as e:
    missing_module = str(e).split("'")[1]
    print(f"[!] Erro: A biblioteca '{missing_module}' não está instalada.")
    print("[!] Instale as dependências executando: pip install requests dnspython python-whois")
    sys.exit(1)

BANNER = """
╔══════════════════════════════════════╗
║        CYBERRECON OSINT              ║
║   Reconhecimento & Inteligência      ║
╚══════════════════════════════════════╝
"""

class CyberReconEngine:
    @staticmethod
    def get_whois(domain: str) -> dict:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.nameservers
            }
        except Exception as e:
            return {"error": f"Falha na consulta WHOIS: {str(e)}"}

    @staticmethod
    def get_dns_records(domain: str) -> dict:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [r.to_text() for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = []
            except Exception as e:
                records[rtype] = [f"Erro: {str(e)}"]
        return records

    @staticmethod
    def search_crtsh(domain: str, timeout: int = 10) -> list:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name.endswith(domain) and not name.startswith('*'):
                            subdomains.add(name)
        except Exception as e:
            return [f"Erro na consulta crt.sh: {str(e)}"]
        
        return sorted(list(subdomains))

    @staticmethod
    def analyze_ip(ip_or_domain: str, timeout: int = 10) -> dict:
        try:
            target_ip = socket.gethostbyname(ip_or_domain)
        except socket.gaierror:
            return {"error": "Não foi possível resolver o endereço IP."}

        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,regionName,city,isp,org,as,query"
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                try:
                    data['reverse_dns'] = socket.gethostbyaddr(target_ip)[0]
                except socket.herror:
                    data['reverse_dns'] = "N/A"
                return data
            return {"error": f"HTTP Error {response.status_code}"}
        except Exception as e:
            return {"error": f"Falha na requisição: {str(e)}"}

    @staticmethod
    def analyze_http(domain: str, timeout: int = 10) -> dict:
        url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        results = {}
        
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent': 'CyberRecon-OSINT/1.0'})
            results['status_code'] = resp.status_code
            results['headers'] = dict(resp.headers)
            results['final_url'] = resp.url
            results['server'] = resp.headers.get('Server', 'Não informado')
        except requests.RequestException as e:
            results['error'] = f"Falha HTTP/HTTPS: {str(e)}"
            
        hostname = domain.replace('https://', '').replace('http://', '').split('/')[0]
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl_issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    results['ssl_expiration'] = cert.get('notAfter')
        except Exception:
            results['ssl_info'] = "Não foi possível obter dados TLS/SSL."

        return results

    @staticmethod
    def extract_metadata(file_path: str) -> dict:
        results = {}
        if not os.path.exists(file_path):
            return {"error": "Arquivo não encontrado."}

        if shutil.which("exiftool"):
            try:
                out = subprocess.check_output(["exiftool", file_path], stderr=subprocess.DEVNULL, text=True)
                results["exiftool"] = out.strip().split("\n")[:20]
            except Exception as e:
                results["exiftool_error"] = str(e)
        else:
            results["exiftool"] = ["ExifTool não encontrado no sistema."]

        if shutil.which("strings"):
            try:
                out = subprocess.check_output(["strings", file_path], stderr=subprocess.DEVNULL, text=True)
                results["strings_sample"] = [line for line in out.split("\n") if len(line) > 8][:10]
            except Exception as e:
                results["strings_error"] = str(e)

        return results

    @staticmethod
    def check_username(username: str, timeout: int = 5) -> dict:
        platforms = {
            "GitHub": "https://api.github.com/users/{}",
            "Reddit": "https://www.reddit.com/user/{}/about.json",
            "DockerHub": "https://hub.docker.com/v2/users/{}/"
        }
        results = {}
        headers = {'User-Agent': 'CyberRecon-OSINT/1.0'}
        
        for platform, url_pattern in platforms.items():
            url = url_pattern.format(username)
            try:
                res = requests.get(url, headers=headers, timeout=timeout)
                results[platform] = "Encontrado" if res.status_code == 200 else "Não encontrado / Indisponível"
            except requests.RequestException:
                results[platform] = "Erro de conexão"
                
        return results

    @staticmethod
    def save_report(data: dict, target: str, output_dir: str = "reports") -> str:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_target = target.replace("/", "_").replace(":", "_")
        filepath = os.path.join(output_dir, f"report_{sanitized_target}_{timestamp}.json")

        report_payload = {
            "metadata": {
                "tool": "CyberRecon OSINT",
                "target": target,
                "datetime": datetime.now().isoformat()
            },
            "results": data
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=4, ensure_ascii=False)

        return filepath

def run_full_scan(target: str) -> dict:
    engine = CyberReconEngine()
    return {
        "whois": engine.get_whois(target),
        "dns": engine.get_dns_records(target),
        "subdomains": engine.search_crtsh(target),
        "ip_info": engine.analyze_ip(target),
        "http_info": engine.analyze_http(target)
    }

def print_menu():
    print(BANNER)
    print("[1] WHOIS & Registros DNS")
    print("[2] Busca Passiva de Subdomínios")
    print("[3] Análise de IP / ASN")
    print("[4] Análise HTTP / Headers / SSL")
    print("[5] Metadados de Arquivo Local")
    print("[6] Presença de Usuário")
    print("[7] Executar Reconhecimento Completo")
    print("[0] Sair\n")

def main():
    parser = argparse.ArgumentParser(description="CyberRecon OSINT - Ferramenta Passiva de Inteligência")
    parser.add_argument("-t", "--target", help="Alvo (Domínio, IP ou Usuário)")
    args = parser.parse_args()

    engine = CyberReconEngine()

    if args.target:
        print(f"[*] Executando varredura passiva completa em: {args.target}")
        results = run_full_scan(args.target)
        report_path = engine.save_report(results, args.target)
        print(f"[+] Relatório salvo em: {report_path}")
        sys.exit(0)

    while True:
        print_menu()
        choice = input("Opção > ").strip()

        if choice == "1":
            domain = input("Domínio (ex: exemplo.com): ").strip()
            print("\n--- WHOIS ---")
            print(engine.get_whois(domain))
            print("\n--- DNS ---")
            print(engine.get_dns_records(domain))
        elif choice == "2":
            domain = input("Domínio: ").strip()
            subs = engine.search_crtsh(domain)
            print(f"\nSubdomínios encontrados ({len(subs)}):")
            for sub in subs:
                print(f" - {sub}")
        elif choice == "3":
            target = input("IP ou Domínio: ").strip()
            print(engine.analyze_ip(target))
        elif choice == "4":
            domain = input("Domínio: ").strip()
            print(engine.analyze_http(domain))
        elif choice == "5":
            path = input("Caminho do arquivo local: ").strip()
            print(engine.extract_metadata(path))
        elif choice == "6":
            username = input("Nome de usuário: ").strip()
            print(engine.check_username(username))
        elif choice == "7":
            target = input("Alvo para varredura completa: ").strip()
            results = run_full_scan(target)
            path = engine.save_report(results, target)
            print(f"\n[+] Varredura concluída! Relatório salvo em: {path}")
        elif choice == "0":
            print("Saindo...")
            break
        else:
            print("Opção inválida.")
        input("\nPressione ENTER para continuar...")

if __name__ == "__main__":
    main()