#!/usr/bin/env python

import ssl, socket, select
from binascii import a2b_base64

class Peer:
    def __init__(self, name, addr, type = "SSL", ssl_cert=None, timeout=5):
        self.name = name
        self.type = type    # currently only TCP or SSL over TCP, but
                            # could be others like dedicated NOISE_XK,
                            # or hybrid mceliece+x25519 over USB or
                            # even UART
        self.address = addr # Currently only TCP host:port as a tuple
        self.ssl_cert = ssl_cert
        self.timeout = timeout
        self.state = "new"
        self.fd = None

    def connect(self):
        if self.state == "connected":
            raise ValueError(f"{self.name} is already connected")

        if self.type not in {"SSL", "TCP"}:
            raise ValueError(f"Unsupported peer type: {self.type}")

        if self.type == "SSL":
           ctx = ssl.create_default_context()
           ctx.minimum_version = ssl.TLSVersion.TLSv1_2
           if(self.ssl_cert):
               ctx.load_verify_locations(self.ssl_cert) # only for dev, production system should use proper certs!
               ctx.check_hostname=False                 # only for dev, production system should use proper certs!
               ctx.verify_mode=ssl.CERT_NONE            # only for dev, production system should use proper certs!
           else:
               ctx.load_default_certs()
               ctx.verify_mode = ssl.CERT_REQUIRED
               ctx.check_hostname = True

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        if self.type == "SSL":
            self.fd = ctx.wrap_socket(s, server_hostname=self.address[0])
        self.fd.connect(self.address)
        self.state="connected"

    def read(self,size):
        if self.state != "connected":
            raise ValueError(f"{self.name} cannot read, is not connected")

        res = []
        read = 0
        while read<size and (len(res)==0 or len(res[-1])!=0):
          res.append(self.fd.recv(size-read))
          read+=len(res[-1])

        if len(res[-1])==0 and read<size:
            self.state = 'disconnected'
            #raise ValueError(f"short read for {self.name}, only {len(b''.join(res))} instead of expected {size} bytes")
        return b''.join(res)

    def send(self, msg):
        self.fd.sendall(msg)

    def close(self):
        if self.state == "closed": return
        if self.fd and self.fd.fileno() != -1:
            try: self.fd.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.fd.close()
            self.state = "closed"
        else:
            # closed by other end.
            self.state = "closed"

class Multiplexer:
    def __init__(self, peers, type="SSL", ssl_cert=None):
        self.peers = [Peer(name, (p['host'],p['port']), type=p.get("type", "SSL"), ssl_cert = p.get('ssl_cert'))
                      for name, p in peers.items()]

    def __getitem__(self, idx):
        return self.peers[idx]

    def __iter__(self):
        for p in self.peers:
            yield p

    def __len__(self):
        return len(self.peers)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        if exception_type is not None:
            print("exception caught", exception_type, exception_value, exception_traceback)
        self.close()

    def connect(self):
       for p in self.peers:
           p.connect()

    def send(self, idx, msg):
        self.peers[idx].send(msg)

    def broadcast(self, msg):
      for p in self.peers:
        p.send(msg)

    def gather(self, expectedmsglen, n=None, proc=None, debug=False):
       fails = []
       if n is None:
           n=len(self.peers)
       responses={}
       for idx, peer in enumerate(self.peers):
           pending = peer.fd.pending()
           if pending == expectedmsglen:
               pkt = peer.read(expectedmsglen)
               if debug: print(f"{idx} got pending {len(pkt)}")
               if pkt == b'\x00\x04fail':
                   responses[idx]=None
                   continue
               responses[idx]=pkt if not proc else proc(pkt)
           #if peer.fd.fileno() < 0:
           #  print(f"{peer} has negative fileno: {peer.fd.fileno()}")
           #elif pending != 0:
           #    print(f"wtf peer {peer.name} has {peer.fd.pending()} bytes pending, which is not equ {expectedmsglen}")
       while len(responses)<n:
          fds={x.fd.fileno(): (i, x) for i,x in enumerate(self.peers) if i not in responses and x.fd.fileno() >= 0}
          if not fds: raise ValueError("not enough peers left to get enough results")
          #print("select")
          r, _,_ =select.select(fds.keys(),[],[],2)
          #print("select done")
          if not r: continue
          #print("got r")
          for fd in r:
             idx = fds[fd][0]
             if idx in responses:
                continue
             #print(f"gathering {idx}")
             pkt = fds[fd][1].read(expectedmsglen)
             if pkt == b'\x00\x04fail':
                 responses[idx]=None
                 continue
             if debug: print(f"{idx} got response of {len(pkt)}")
             tmp = pkt if not proc else proc(pkt)
             if tmp is None: continue
             responses[idx]=tmp
       if set((tuple(e) if isinstance(e,list) else e) for e in responses.values())=={None}:
           raise ValueError("oracles failed")
       if None in responses.values():
           if debug: print(f"some reponses failed")
           #return {k:v for k,v in responses.items() if v is not None}
       return [responses.get(i,None) for i in range(len(self.peers))]
       #return responses

    def close(self):
      for p in self.peers:
        p.close()
