#!/usr/bin/env python3
"""TLS file server for on-device trigger delivery. LAB env = lab scratch dir.

Usage: python3 tls_server.py <port> <webroot-dir>
Files in DOWNLOAD get Content-Disposition: attachment (Safari downloads instead of
inline-rendering and crashing the renderer mid-download). Extend DOWNLOAD per campaign.
"""
import http.server, ssl, sys, functools, os

LAB = os.environ.get('LAB', '/home/box/.hermes/profiles/seraphine/cache/scratch')
DOWNLOAD = {'gA.pdf', 'gB.pdf', 'a64.tiff', 'a128.tiff', 'a64.png'}

class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        fn = os.path.basename(self.path.split('?')[0])
        if fn in DOWNLOAD:
            self.send_header('Content-Disposition', 'attachment; filename="%s"' % fn)
        super().end_headers()

port = int(sys.argv[1]); dirv = sys.argv[2]
httpd = http.server.ThreadingHTTPServer(('0.0.0.0', port), functools.partial(H, directory=dirv))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(LAB + '/cert.pem', LAB + '/key.pem')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f'https on :{port} serving {dirv}', flush=True)
httpd.serve_forever()
