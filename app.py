from flask import Flask, jsonify, request
from markupsafe import escape
import socket
import requests
from urllib.parse import urlparse
import json



app = Flask(__name__)
@app.route("/portscan", methods=['POST'])
def scanner_de_portas():

    data = request.get_json()
    ip = data.get("ip")
    port = data.get("port")

    if ip == "localhost" or ip == "127.0.0.1":
        return "A varredura de localhost não é permitida."

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Define o tempo limite para a conexão
    resultado = sock.connect_ex((ip, port))
    if resultado == 0:
        result = {
            "port": f"{escape(port)}",
            "ip": f"{escape(ip)}",
            "status": "open"
                }

        return result

    else:
        result = {
            "port": f"{escape(port)}",
            "ip": f"{escape(ip)}",
            "status": "closed"
                }

        return result

    sock.close()




# ========================Verificar_cdn================================


cdn_list = [
    ("Akamai", "akamai.net"),
    ("Cloudflare", "cloudflare.com"),
    ("Fastly", "fastly.net"),
    ("MaxCDN", "maxcdn.com"),
    ("Amazon CloudFront", "cloudfront.net"),
    ("Incapsula", "incapdns.net"),
    ("EdgeCast", "edgecastcdn.net"),
    ("KeyCDN", "kxcdn.com"),
    ("StackPath", "stackpathdns.com"),
    ("Limelight", "llnw.com"),
    ("CDN77", "cdn77.org"),
    ("Level 3", "footprint.net"),
    ("CDNetworks", "cdngc.net"),
    ("CacheFly", "cachefly.net"),
    ("Highwinds", "hwcdn.net"),
    ("OnApp", "r.worldssl.net"),
    ("Tencent Cloud", "tencent-cloud.net"),
    ("Alibaba Cloud", "alicdn.com"),
    ("Google Cloud", "googleusercontent.com"),
    ("Microsoft Azure", "azureedge.net"),
    ("CloudSigma", "cloudsigma.com"),
    ("G-Core Labs", "core.pw"),
    ("BunnyCDN", "b-cdn.net"),
    ("ArvanCloud", "arvan.cloud"),
    ("Swarmify", "swarmcdn.com"),
    ("BelugaCDN", "belugacdn.link"),
    ("CDNify", "cdnify.io"),
    ("Cloudinary", "cloudinary.com"),
    ("KeyCDN", "keycdn.com"),
    ("OnApp", "onappcdn.com"),
    ("Sucuri", "sucuri.net"),
    ("CloudFront", "cloudfront.net"),
    ("CDN77", "cdn77.com"),
    ("Section.io", "section.io"),
    ("Cachefly", "cachefly.net"),
    ("Quantil", "quantil.com"),
    ("Incapsula", "incapsula.com"),
    # Adicione outros serviços de CDN conforme necessário
]

def is_cdn(domain):
    for cdn, cdn_domain in cdn_list:
        if domain == cdn_domain or domain.endswith("." + cdn_domain):
            return cdn
    return None

def verifica_cdn(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    result = {
        "url": url,
        "cdn_detected": False,
        "cdn_service": None,
        "subdomains": []
    }

    try:
        response = requests.head(url, headers=headers, allow_redirects=True)
        if "Server" in response.headers:
            server_header = response.headers["Server"]
            for cdn, cdn_domain in cdn_list:
                if cdn.lower() in server_header.lower():
                    result["cdn_detected"] = True
                    result["cdn_service"] = cdn
                    break

        if "X-Cache" in response.headers or "X-CDN" in response.headers or "X-Cache-Status" in response.headers:
            result["additional_headers_detected"] = True

        parsed_url = urlparse(url)
        subdomains = parsed_url.hostname.split(".")
        result["subdomains"] = subdomains

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return json.dumps(result)





@app.route('/verificar_cdn', methods=['GET'])
def verificar_cdn():
    url = request.args.get('url')

    if url:
        resultado = verifica_cdn(url)
        return jsonify(json.loads(resultado))
    else:
        return jsonify({'error': 'URL não fornecida'})

if __name__ == "__main__":
    app.run()