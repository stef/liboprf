#!/usr/bin/env python

import ssl, socket, select, struct, asyncio
from pyoprf import noisexk
from itertools import zip_longest
try:
    from ble_serial.bluetooth.ble_client import BLE_client
except:
    BLE_client = None

def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n))

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
        try: self.fd.connect(self.address)
        except: return
        self.state="connected"

    def connected(self):
        return self.state == "connected"

    async def read_async(self,size):
        if not self.connected():
            return None
            #raise ValueError(f"{self.name} cannot read, is not connected")

        res = []
        read = 0
        while read<size and (len(res)==0 or len(res[-1])!=0):
          res.append(self.fd.recv(size-read))
          read+=len(res[-1])

        if len(res[-1])==0 and read<size:
            self.state = 'disconnected'
            #raise ValueError(f"short read for {self.name}, only {len(b''.join(res))} instead of expected {size} bytes")
        return b''.join(res)

    def read(self, *args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(self.read_async(*args, **kwargs))

    def send(self, msg):
        if not self.connected():
            return
            #raise ValueError(f"{self.name} cannot write, is not connected")
        self.fd.sendall(msg)

    def close(self):
        if self.state == "closed": return
        if not self.connected():
            return
            #raise ValueError(f"{self.name} cannot close, is not connected")
        if self.fd and self.fd.fileno() != -1:
            try: self.fd.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.fd.close()
            self.state = "closed"
        else:
            # closed by other end.
            self.state = "closed"

class BLEPeer:
    def __init__(self, name, addr, server_pk, client_sk, device="hci0", timeout=5):
        self.name = name
        self.address = addr # the MAC address of the device
        self.server_pk = server_pk
        self.client_sk = client_sk
        self.timeout = timeout
        self.state = "new"
        self.ble = BLE_client(device, None)
        self.rx_buffer = []
        self.rx_len = 0
        self.rx_pexted = 0
        self.rx_available = asyncio.Event()

    def receive_callback(self, value: bytes):
         #print("Received:", len(value), self.rx_pected, self.rx_len, value.hex(), file=sys.stderr)
         #if self.rx_pected == 0:
         #    raise Exception(f"unexpected input received: {value.hex()}")
         #self.rx_queue.put(value)
         self.rx_buffer.append(value)
         self.rx_len += len(value)
         #if(self.rx_pected < 0):
         #    exit(23)
         #    raise Exception("rx buffer overflow")
         if self.rx_pected > 0 and self.rx_len >= self.rx_pected:
             self.rx_available.set()

    async def read_raw(self,size):
        while(self.rx_available.is_set()): pass
        self.rx_pected = size
        if(self.rx_len < self.rx_pected):
            #print(f"{self.rx_len} < {self.rx_pected}", file=sys.stderr)
            await self.rx_available.wait()
        rsize = 0;
        ret = []
        while(rsize<self.rx_pected):
           ret.append(self.rx_buffer.pop(0))
           rsize+=len(ret[-1])
        ret = b''.join(ret)
        self.rx_pected = 0
        self.rx_len -= rsize
        self.rx_available.clear()
        return ret

    async def _send(self, msg, mtu=20):
    #def _send(self, msg, mtu=20):
        #print(f"_sending {msg.hex()}", file=sys.stderr)
        for frag in split_by_n(msg, mtu):
            frag=bytes(c for c in frag if c is not None)
            #print("sending frag", repr(frag))
            #self.ble.queue_send(frag)
            await self.ble.dev.write_gatt_char(self.ble.write_char, frag, self.ble.write_response_required)
            #print(f"sent: {frag.hex()}", file=sys.stderr)

    async def _connect(self):
        if self.state == "connected":
            raise ValueError(f"{self.name} is already connected")

        self.ble.set_receiver(self.receive_callback)

        await self.ble.connect(self.address, "public", None, 10.0)
        await self.ble.setup_chars(None, None, "rw", False)

        self.session, msg = noisexk.initiator_session(self.client_sk, self.server_pk, dst=b"klutshnik ble tle")
        await self._send(msg)
        resp = await self.read_raw(48)
        noisexk.initiator_session_complete(self.session, resp)
        ct = noisexk.send_msg(self.session, "")
        await self._send(ct)

        self.state="connected"

    async def _disconnect(self):
        await self.ble.disconnect()
        self.state == "disconnected"

    def connect(self):
        asyncio.get_event_loop().set_debug(True)
        asyncio.get_event_loop().run_until_complete(self._connect())
        while not self.connected(): pass

    def connected(self):
        return self.state == "connected"

    def read(self,size):
        if not self.connected():
            return None
            #raise ValueError(f"{self.name} cannot read, is not connected")
        ct = asyncio.get_event_loop().run_until_complete(self.read_raw(size+16))
        return noisexk.read_msg(self.session, ct)

    async def read_async(self, size):
        if not self.connected():
            return None
        resp = await self.read_raw(size+16)
        return noisexk.read_msg(self.session, resp)

    def send(self, msg):
        #print("sending msg", msg.hex(), file=sys.stderr)
        if not self.connected():
            return
            #raise ValueError(f"{self.name} cannot write, is not connected")
        ct = noisexk.send_msg(self.session, msg)
        header = struct.pack(">H",len(ct))
        asyncio.get_event_loop().run_until_complete(self._send(header+ct))

    def close(self):
        if self.state == "closed": return
        if not self.connected():
            return
            #raise ValueError(f"{self.name} cannot close, is not connected")
        asyncio.get_event_loop().run_until_complete(self._disconnect())

class Multiplexer:
    def __init__(self, peers):
        if asyncio.get_event_loop_policy()._local._loop is None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.peers = []
        for name, p in peers.items():
            if 'port' in p:
                p = Peer(name
                         ,(p['host'],p['port'])
                         ,type=p.get("type", "SSL")
                         ,ssl_cert = p.get('ssl_cert')
                         ,timeout = p.get('timeout'))
            elif 'bleaddr' in p:
                p = BLEPeer(name
                            ,p['bleaddr']
                            ,p['device_pk']
                            ,p['client_sk']
                            ,timeout=p.get('timeout'))
            else:
                raise ValueError(f"cannot decide type of peer: {name}")
            self.peers.append(p)

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

    async def gather_async(self, expected_msg_len, n=None, proc=None):
        results = await asyncio.gather(
            *[peer.read_async(expected_msg_len) for peer in self.peers], return_exceptions=True
        )
        for i in range(len(results)):
            if isinstance(results[i], Exception):
                results[i]=None
                continue
            if results[i] == b'\x00\x04fail':
                results[i]=None
                continue
            tmp = results[i] if not proc else proc(results[i])
            if tmp is None: continue
            results[i]=tmp

        if n is None:
            n=len(self.peers)
        if len([1 for e in results if e is not None]) < n:
            raise ValueError(f"not enough responses gathered: {results}")
        return results

    def gather(self, *args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(self.gather_async(*args, **kwargs))

    def close(self):
      for p in self.peers:
        p.close()
