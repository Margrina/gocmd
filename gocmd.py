#!/usr/bin/env python3
"""gocmd - private, end-to-end encrypted channel chat for the command line.

No server to run: `gocmd --new` hosts the channel on your own computer and opens a
public tunnel for it. The only central piece is the ban server (bans, unbans, updates).

Usage:
    gocmd -u NAME --new          create a new channel
    gocmd -u NAME -o CODE        join a channel with a one-time code

Inside a channel:
    /onecode               one-time join code (shown only to you, 3 min, single use)
    /vote.kick.ALIAS       start a kick vote against ALIAS
    /vote.ALIAS            vote YES in the running vote against ALIAS
    /vote.no.ALIAS         vote NO  in the running vote against ALIAS
    /members               list aliases in the channel
    /exit                  leave
"""
VERSION = "2.2.0"

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import string
import struct
import sys
import threading
import time
import urllib.request
import uuid
import webbrowser

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "gocmd_config.json")
MAX_FRAME = 1 << 20
PAD_TRANSPORT = 1024   # every wire frame is a multiple of 1 KiB -> message length is hidden
PAD_MSG = 256          # every chat message ciphertext is a multiple of 256 bytes
CLEAR_EVERY = 10       # wipe the screen after every 10 chat messages
INVITE_TTL = 180
IDLE_KICK = 7 * 60
IDLE_WARN = 6 * 60
POLL_TIME = 60
VOTE_COOLDOWN = 180
VOTE_MAX_FAILS = 3
BAN_RECHECK = 60
TUNNEL_HOST = "bore.pub"
BORE_PORT = 7835
ALIAS_CHARS = string.ascii_letters + string.digits + "%#$@&*!"

# Screen recording / screenshot software. Running at startup -> gocmd refuses to start.
# Opened while you are inside a channel -> 24h ban. Extend with "extra_blocked_processes".
RECORDERS = {
    "obs64.exe", "obs32.exe", "obs.exe", "streamlabs obs.exe", "streamlabs desktop.exe",
    "xsplit.core.exe", "xsplit.broadcaster.exe", "bandicam.exe", "bdcam.exe",
    "camtasia.exe", "camtasiastudio.exe", "camrecorder.exe", "sharex.exe", "greenshot.exe",
    "lightshot.exe", "snippingtool.exe", "screenclippinghost.exe", "screensketch.exe",
    "snagit32.exe", "snagiteditor.exe", "snagitcapture.exe", "fraps.exe", "screentogif.exe",
    "gyazo.exe", "gyazowin.exe", "gyazoreplay.exe", "loom.exe", "flameshot.exe", "dxtory.exe",
    "apowerrec.exe", "apowersoft screen recorder.exe", "icecreamscreenrecorder.exe",
    "recmaster.exe", "screenrec.exe", "screencast-o-matic.exe", "som.exe", "debut.exe",
    "ffmpeg.exe", "gamebar.exe", "gamebarftserver.exe", "nvidia share.exe", "action.exe",
    "mirillis action.exe", "playclaw.exe", "movavi screen recorder.exe", "screenpresso.exe",
    "picpick.exe", "faststone capture.exe", "fscapture.exe", "screenpal.exe", "vokoscreen.exe",
    "kazam", "simplescreenrecorder", "obs", "gnome-screenshot", "spectacle", "peek",
}


# ================================================================== crypto helpers
def hkdf(secret, info, length=32, salt=None):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def raw_pub(key):
    if hasattr(key, "public_key"):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_priv(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def fingerprint(pub):
    return base64.b32encode(hashlib.sha256(b"gocmd-fpr" + pub).digest()[:10]).decode()


def pad(data, block):
    body = struct.pack(">I", len(data)) + data
    total = -(-len(body) // block) * block
    return body + secrets.token_bytes(total - len(body))


def unpad(data):
    n = struct.unpack(">I", data[:4])[0]
    if n > len(data) - 4:
        raise ValueError("bad padding")
    return data[4:4 + n]


class Session:
    """Transport layer: after the key exchange every byte on the wire is ChaCha20-Poly1305
    ciphertext padded to 1 KiB blocks. Wireshark sees random bytes."""

    def __init__(self, send_key, recv_key):
        self._s, self._r = ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key)
        self._sn = self._rn = 0

    def seal(self, obj):
        pt = pad(json.dumps(obj, separators=(",", ":")).encode(), PAD_TRANSPORT)
        nonce = struct.pack(">4xQ", self._sn)
        self._sn += 1
        ct = self._s.encrypt(nonce, pt, None)
        return struct.pack(">I", len(ct)) + ct

    def open(self, ct):
        nonce = struct.pack(">4xQ", self._rn)
        self._rn += 1
        return json.loads(unpad(self._r.decrypt(nonce, ct, None)))


def derive_session(dh_static, dh_eph, c_eph, s_eph, is_client):
    km = hkdf(dh_static + dh_eph, b"gocmd-transport-v2", 64, salt=c_eph + s_eph)
    c2s, s2c = km[:32], km[32:]
    return Session(c2s, s2c) if is_client else Session(s2c, c2s)


def e2e_encrypt(key, cid, text):
    nonce = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(bytes(key)).encrypt(nonce, pad(text.encode(), PAD_MSG), cid.encode())
    return base64.b64encode(nonce + ct).decode()


def e2e_decrypt(key, cid, b64):
    raw = base64.b64decode(b64)
    return unpad(ChaCha20Poly1305(bytes(key)).decrypt(raw[:12], raw[12:], cid.encode())).decode()


def new_secret():
    s = base64.b32encode(secrets.token_bytes(15)).decode()          # 120 random bits
    return "-".join(s[i:i + 4] for i in range(0, 24, 4))


def parse_code(code):
    """SECRET@HOST:PORT/FINGERPRINT -> (secret, relay address, relay fingerprint)."""
    secret, _, rest = code.strip().partition("@")
    addr, _, fpr = rest.partition("/")
    if not addr or ":" not in addr or len(fpr) != 16:
        raise ValueError("bad code")
    return secret, addr, fpr.upper()


def code_material(secret):
    """One-time secret -> (lookup id the host sees, wrap key the host never sees)."""
    raw = base64.b32decode(secret.split("@", 1)[0].replace("-", "").replace(" ", "").upper())
    if len(raw) != 15:
        raise ValueError("bad code")
    return hashlib.sha256(b"gocmd-lookup" + raw).hexdigest(), hkdf(raw, b"gocmd-wrap")


def wrap_key(wrap, key):
    nonce = secrets.token_bytes(12)
    return base64.b64encode(nonce + ChaCha20Poly1305(wrap).encrypt(nonce, bytes(key), b"invite")).decode()


def unwrap_key(wrap, blob):
    raw = base64.b64decode(blob)
    return bytearray(ChaCha20Poly1305(wrap).decrypt(raw[:12], raw[12:], b"invite"))


def vt(v):
    return tuple(int(x) for x in str(v).split(".") if x.isdigit())


# ================================================================== client connection
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


class Conn:
    def __init__(self, server, pin_pub=None, pin_fpr=None):
        host, port = server.rsplit(":", 1)
        self.sock = socket.create_connection((host, int(port)), timeout=20)
        eph = X25519PrivateKey.generate()
        c_eph = raw_pub(eph)
        self.sock.sendall(c_eph)
        hdr = recv_exact(self.sock, 64)
        s_static, s_eph = hdr[:32], hdr[32:]
        if (pin_pub and s_static != pin_pub) or (pin_fpr and fingerprint(s_static) != pin_fpr):
            self.sock.close()
            raise ConnectionError("channel host identity does not match the code (possible interception)")
        dh_static = eph.exchange(X25519PublicKey.from_public_bytes(s_static))
        dh_eph = eph.exchange(X25519PublicKey.from_public_bytes(s_eph))
        self.sess = derive_session(dh_static, dh_eph, c_eph, s_eph, True)
        self.sock.settimeout(None)
        self.lock = threading.Lock()

    def send(self, obj):
        with self.lock:
            self.sock.sendall(self.sess.seal(obj))

    def recv(self):
        n = struct.unpack(">I", recv_exact(self.sock, 4))[0]
        if n > MAX_FRAME:
            raise ConnectionError("frame too large")
        try:
            return self.sess.open(recv_exact(self.sock, n))
        except InvalidTag:
            raise ConnectionError("channel host failed authentication")

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ================================================================== built-in channel host
class Peer:
    def __init__(self, reader, writer, sess):
        self.reader, self.writer, self.sess = reader, writer, sess
        self.lock = asyncio.Lock()
        self.closed = False
        self.alias = None
        self.last_active = time.time()
        self.warned = False
        self.bad_joins = 0

    async def send(self, obj):
        if self.closed:
            return
        try:
            async with self.lock:
                self.writer.write(self.sess.seal(obj))
                await self.writer.drain()
        except (ConnectionError, OSError):
            self.closed = True

    async def recv(self):
        n = struct.unpack(">I", await self.reader.readexactly(4))[0]
        if n > 64 * 1024:
            raise ConnectionError("frame too large")
        return self.sess.open(await self.reader.readexactly(n))

    def close(self):
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass


class Relay:
    """Hosts exactly one channel, in RAM, on the creator's computer. It routes ciphertext and
    enforces the rules (invites, votes, idle kicks); it never has the channel key."""

    def __init__(self):
        self.static = X25519PrivateKey.generate()          # fresh identity per channel
        self.pub = raw_pub(self.static)
        self.fpr = fingerprint(self.pub)
        self.cid = secrets.token_hex(16)
        self.members = {}        # alias -> Peer
        self.invites = {}        # lookup -> (blob, expires)
        self.polls = {}          # target alias -> poll
        self.fails = {}          # alias -> failed kick votes
        self.cooldown = {}       # alias -> unix time
        self.started = False     # becomes True when the creator is inside
        self.dead = False        # True forever once the last member left
        self.public = None

    async def sys(self, text, exclude=None):
        for p in list(self.members.values()):
            if p is not exclude:
                await p.send({"type": "sys", "text": text})

    def resolve(self, s):
        s = s.strip()
        if s in self.members:
            return s
        hits = [a for a in self.members if a.startswith(s)] if len(s) >= 3 else []
        return hits[0] if len(hits) == 1 else None

    async def remove(self, peer, why="left"):
        if self.members.get(peer.alias) is not peer:
            return
        del self.members[peer.alias]
        self.polls.pop(peer.alias, None)
        for poll in self.polls.values():
            poll["yes"].discard(peer.alias)
            poll["no"].discard(peer.alias)
        if not self.members:
            self.dead = True                 # channel gone forever
            self.invites.clear()
        else:
            await self.sys(f"{peer.alias} {why}.")

    async def kick(self, peer, text, why):
        await peer.send({"type": "kicked", "text": text})
        await self.remove(peer, why)
        peer.close()

    async def resolve_poll(self, target):
        poll = self.polls.pop(target, None)
        if not poll:
            return
        yes, no = len(poll["yes"]), len(poll["no"])
        victim = self.members.get(target)
        if victim and yes >= 1 and yes > no:
            await self.kick(victim, f"You were kicked by vote ({yes} yes / {no} no).",
                            f"was kicked by vote ({yes} yes / {no} no)")
            return
        who = poll["by"]
        self.fails[who] = self.fails.get(who, 0) + 1
        self.cooldown[who] = time.time() + VOTE_COOLDOWN
        await self.sys(f"Kick vote against {target} failed ({yes} yes / {no} no).")

    async def dispatch(self, peer, m):
        t = m.get("type")
        if t == "join":
            if peer.alias:
                return
            inv = self.invites.pop(str(m.get("lookup")), None)
            if self.dead or not inv or inv[1] < time.time():
                peer.bad_joins += 1
                await peer.send({"type": "error", "text": "Invalid, used or expired code."})
                if peer.bad_joins >= 5:
                    peer.close()
                return
            while True:
                peer.alias = "".join(secrets.choice(ALIAS_CHARS) for _ in range(16))
                if peer.alias not in self.members:
                    break
            peer.last_active = time.time()
            self.members[peer.alias] = peer
            self.started = True
            await peer.send({"type": "joined", "cid": self.cid, "alias": peer.alias,
                             "members": list(self.members), "blob": inv[0]})
            await self.sys(f"{peer.alias} joined.", exclude=peer)
            return
        if not peer.alias:
            return
        if t == "msg":
            ct = m.get("ct")
            if not isinstance(ct, str) or len(ct) > 16000:
                return
            peer.last_active, peer.warned = time.time(), False
            for other in list(self.members.values()):
                if other is not peer:
                    await other.send({"type": "msg", "from": peer.alias, "ct": ct})
        elif t == "invite_put":
            lookup, blob = str(m.get("lookup", "")), str(m.get("blob", ""))
            if len(lookup) != 64 or len(blob) > 200:
                return
            now = time.time()
            self.invites = {k: v for k, v in self.invites.items() if v[1] > now}
            self.invites[lookup] = (blob, now + INVITE_TTL)
            await peer.send({"type": "invite_ok", "lookup": lookup})
        elif t == "members":
            await peer.send({"type": "sys", "text": "Members: " + ", ".join(self.members)})
        elif t == "vote_kick":
            target = self.resolve(str(m.get("target", "")))
            err = None
            if not target:
                err = "No such member."
            elif target == peer.alias:
                err = "You can't vote to kick yourself."
            elif self.fails.get(peer.alias, 0) >= VOTE_MAX_FAILS:
                err = "You used all 3 failed kick votes."
            elif self.cooldown.get(peer.alias, 0) > time.time():
                err = f"Kick vote cooldown: {int(self.cooldown[peer.alias] - time.time())}s left."
            elif target in self.polls:
                err = "A vote against them is already running."
            if err:
                return await peer.send({"type": "error", "text": err})
            self.polls[target] = {"by": peer.alias, "yes": set(), "no": set(), "ends": time.time() + POLL_TIME}
            await self.sys(f"VOTE: kick {target}? Type /vote.{target} (yes) or /vote.no.{target} (no). "
                           f"{POLL_TIME}s. Not voting = not counted.")
        elif t == "vote":
            target = self.resolve(str(m.get("target", "")))
            if not target or target not in self.polls:
                return await peer.send({"type": "error", "text": "No running vote against that member."})
            if target == peer.alias:
                return await peer.send({"type": "error", "text": "You can't vote on your own kick."})
            poll = self.polls[target]
            poll["no" if m.get("yes") else "yes"].discard(peer.alias)
            poll["yes" if m.get("yes") else "no"].add(peer.alias)
            await peer.send({"type": "sys", "text": "Vote counted."})
            if len(poll["yes"]) + len(poll["no"]) >= len(self.members) - 1:
                await self.resolve_poll(target)
        elif t == "leave":
            await self.remove(peer)
            peer.close()

    async def handle(self, reader, writer):
        peer = None
        try:
            c_eph = await asyncio.wait_for(reader.readexactly(32), 20)
            eph = X25519PrivateKey.generate()
            s_eph = raw_pub(eph)
            writer.write(self.pub + s_eph)
            await writer.drain()
            cpub = X25519PublicKey.from_public_bytes(c_eph)
            sess = derive_session(self.static.exchange(cpub), eph.exchange(cpub), c_eph, s_eph, False)
            peer = Peer(reader, writer, sess)
            hello = await asyncio.wait_for(peer.recv(), 20)
            if hello.get("type") != "hello" or self.dead:
                return
            await peer.send({"type": "ok"})
            while not peer.closed:
                m = await asyncio.wait_for(peer.recv(), IDLE_KICK + 120)
                if isinstance(m, dict):
                    await self.dispatch(peer, m)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError,
                InvalidTag, ValueError, KeyError, TypeError):
            pass
        finally:
            if peer:
                await self.remove(peer)
                peer.close()
            else:
                writer.close()

    async def ticker(self):
        while True:
            await asyncio.sleep(2)
            now = time.time()
            for target, poll in list(self.polls.items()):
                if poll["ends"] <= now:
                    await self.resolve_poll(target)
            for p in list(self.members.values()):
                idle = now - p.last_active
                if idle >= IDLE_KICK:
                    await self.kick(p, "Kicked: no message for 7 minutes.", "was kicked for inactivity")
                elif idle >= IDLE_WARN and not p.warned:
                    p.warned = True
                    await p.send({"type": "sys", "text": "Send a message within 1 minute or you will be kicked."})

    # -- tunnel: speaks the open bore protocol to bore.pub, so the channel gets a public
    #    address with no port forwarding. bore.pub only carries encrypted bytes.
    @staticmethod
    async def _bsend(w, obj):
        w.write(json.dumps(obj).encode() + b"\0")
        await w.drain()

    @staticmethod
    async def _brecv(r):
        return json.loads((await r.readuntil(b"\0"))[:-1])

    async def _accept(self, host, uid):
        try:
            r, w = await asyncio.open_connection(host, BORE_PORT)
            await self._bsend(w, {"Accept": uid})
            await self.handle(r, w)
        except (OSError, asyncio.IncompleteReadError):
            pass

    async def tunnel(self, host, ready):
        while not self.dead:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, BORE_PORT), 15)
                await self._bsend(w, {"Hello": 0})
                m = await asyncio.wait_for(self._brecv(r), 15)
                if not isinstance(m, dict) or "Hello" not in m:
                    raise ConnectionError(str(m))
                self.public = f"{host}:{m['Hello']}"
                ready.set()
                while not self.dead:
                    m = await asyncio.wait_for(self._brecv(r), 60)
                    if isinstance(m, dict) and "Connection" in m:
                        asyncio.create_task(self._accept(host, m["Connection"]))
                    elif isinstance(m, dict) and "Error" in m:
                        raise ConnectionError(m["Error"])
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, ConnectionError):
                self.public = None
                await asyncio.sleep(5)


class Host:
    """Runs a Relay on a background thread of this process."""

    def __init__(self, tunnel_host=TUNNEL_HOST):
        self.relay = Relay()
        self.tunnel_host = tunnel_host
        self.port = None
        self.loop = asyncio.new_event_loop()

    def start(self, timeout=25):
        listening, tunnel_up = threading.Event(), threading.Event()

        async def boot():
            server = await asyncio.start_server(self.relay.handle, "127.0.0.1", 0)
            self.port = server.sockets[0].getsockname()[1]
            asyncio.create_task(self.relay.ticker())
            asyncio.create_task(self.relay.tunnel(self.tunnel_host, tunnel_up))
            listening.set()
            async with server:
                await server.serve_forever()

        threading.Thread(target=lambda: self.loop.run_until_complete(boot()), daemon=True).start()
        listening.wait(10)
        return tunnel_up.wait(timeout)

    def add_invite(self, lookup, blob):
        self.relay.invites[lookup] = (blob, time.time() + INVITE_TTL)

    def others(self):
        return len(self.relay.members)


# ================================================================== config + ban server
def load_config():
    if not os.path.exists(CONFIG_PATH):
        sys.exit(f"Missing {CONFIG_PATH} - it comes with gocmd.")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def id_hash(kind, value):
    return hashlib.sha256(f"gocmd-id-v1|{kind}|{str(value).strip().lower()}".encode()).hexdigest()


def machine_identity():
    macs = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == psutil.AF_LINK and a.address:
                    macs.add(a.address.replace("-", ":").lower())
    except Exception:
        pass
    node = uuid.getnode()
    macs.add(":".join(f"{(node >> s) & 0xff:02x}" for s in range(40, -1, -8)))
    macs = {m for m in macs if m.strip("0:") and len(m) == 17}
    return socket.gethostname(), sorted(macs)[:16]


JUNK_IDS = {"", "default string", "to be filled by o.e.m.", "none", "system serial number", "0",
            "not applicable", "n/a", "unknown", "123456789", "0123456789", "base board serial number",
            "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"}


def hardware_ids():
    """Identifiers that survive deleting gocmd, renaming the PC, changing MAC and even
    reinstalling Windows: motherboard UUID, board serial, BIOS serial, disk serials."""
    found = []
    if os.name == "nt":
        import subprocess
        ps = ("$u=(Get-CimInstance Win32_ComputerSystemProduct).UUID;$b=(Get-CimInstance Win32_BIOS).SerialNumber;"
              "$m=(Get-CimInstance Win32_BaseBoard).SerialNumber;$d=@(Get-CimInstance Win32_DiskDrive|%{$_.SerialNumber});"
              "@{uuid=$u;bios=$b;board=$m;disks=$d}|ConvertTo-Json -Compress")
        try:
            d = json.loads(subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                                          text=True, timeout=30).stdout or "{}")
        except Exception:
            d = {}
        found += [("uuid", d.get("uuid")), ("bios", d.get("bios")), ("board", d.get("board"))]
        disks = d.get("disks") or []
        found += [("disk", x) for x in (disks if isinstance(disks, list) else [disks])]
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                found.append(("winguid", winreg.QueryValueEx(k, "MachineGuid")[0]))
        except OSError:
            pass
    else:
        for kind, path in (("uuid", "/sys/class/dmi/id/product_uuid"), ("board", "/sys/class/dmi/id/board_serial"),
                           ("winguid", "/etc/machine-id")):
            try:
                found.append((kind, open(path).read()))
            except OSError:
                pass
    return [id_hash(k, str(v).strip().strip(".")) for k, v in found
            if v and str(v).strip().strip(".").lower() not in JUNK_IDS]


def device_token():
    """A random ID kept in several places OUTSIDE the gocmd folder, so deleting the tool
    does not reset it. If any copy survives, the others are restored."""
    tok, files, reg = None, [], None
    if os.name == "nt":
        for env in ("LOCALAPPDATA", "APPDATA"):
            if os.environ.get(env):
                files.append(os.path.join(os.environ[env], "gocmd", "device.id"))
        try:
            import winreg
            reg = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\gocmd")
            tok = winreg.QueryValueEx(reg, "device")[0]
        except OSError:
            pass
    else:
        files += [os.path.expanduser("~/.config/gocmd/device.id"), os.path.expanduser("~/.local/share/gocmd/device.id")]
    for f in files:
        if not tok:
            try:
                tok = open(f).read().strip()
            except OSError:
                pass
    if not (isinstance(tok, str) and len(tok) == 64):
        tok = secrets.token_hex(32)
    for f in files:
        try:
            os.makedirs(os.path.dirname(f), exist_ok=True)
            with open(f, "w") as fh:
                fh.write(tok)
        except OSError:
            pass
    if reg:
        try:
            import winreg
            winreg.SetValueEx(reg, "device", 0, winreg.REG_SZ, tok)
            reg.Close()
        except OSError:
            pass
    return id_hash("token", tok)


_IDS = None


def my_ids():
    """Everything a ban is tied to: hostname, MACs, hardware IDs and the device token."""
    global _IDS
    if _IDS is None:
        host, macs = machine_identity()
        ids = [id_hash("host", host)] + [id_hash("mac", m) for m in macs] + hardware_ids() + [device_token()]
        _IDS = list(dict.fromkeys(ids))[:40]
    return _IDS


def ban_api(cfg, path, body):
    req = urllib.request.Request(
        cfg["ban_server"].rstrip("/") + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": f"gocmd/{VERSION}",
                 "ngrok-skip-browser-warning": "1"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


# ================================================================== local protection
def running_processes():
    try:
        import psutil
        return {(p.info["name"] or "").lower() for p in psutil.process_iter(["name"])}
    except ImportError:
        import csv
        import subprocess
        out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
        return {row[0].lower() for row in csv.reader(out.splitlines()) if row}


class Guard:
    def __init__(self, cfg):
        self.blocked = RECORDERS | {p.lower() for p in cfg.get("extra_blocked_processes", [])}

    def scan(self):
        return sorted(running_processes() & self.blocked)

    @staticmethod
    def wipe_clipboard_images():
        """Screenshots taken with PrintScreen land in the clipboard as images: wipe them."""
        if os.name != "nt":
            return
        import ctypes
        u = ctypes.windll.user32
        if any(u.IsClipboardFormatAvailable(f) for f in (2, 8, 17)):   # CF_BITMAP, CF_DIB, CF_DIBV5
            if u.OpenClipboard(None):
                try:
                    u.EmptyClipboard()
                finally:
                    u.CloseClipboard()


# ================================================================== console UI
class Console:
    def __init__(self, header):
        self.lock = threading.RLock()
        self.buf = []
        self.prompt = "> "
        self.count = 0
        self.header = header
        if os.name == "nt":
            os.system("")          # enable ANSI escape codes in the Windows console

    def _redraw(self):
        sys.stdout.write("\r\x1b[2K" + self.prompt + "".join(self.buf))
        sys.stdout.flush()

    def clear(self, show_header=True):
        with self.lock:
            os.system("cls" if os.name == "nt" else "clear")
            sys.stdout.write("\x1b[3J\x1b[2J\x1b[H")       # also wipes scrollback
            if show_header:
                sys.stdout.write(self.header + "\n")
            sys.stdout.flush()

    def show(self, line, chat=False):
        with self.lock:
            if chat:
                if self.count >= CLEAR_EVERY:
                    self.clear()
                    self.count = 0
                self.count += 1
            sys.stdout.write("\r\x1b[2K" + line + "\n")
            self._redraw()

    def readline(self, stop):
        if os.name != "nt":
            try:
                return input(self.prompt)
            except EOFError:
                return None
        import msvcrt
        self._redraw()
        while not stop.is_set():
            if not msvcrt.kbhit():
                time.sleep(0.02)
                continue
            ch = msvcrt.getwch()
            with self.lock:
                if ch in ("\r", "\n"):
                    line = "".join(self.buf)
                    self.buf = []
                    sys.stdout.write("\r\x1b[2K")
                    sys.stdout.flush()
                    return line
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch == "\x08":
                    if self.buf:
                        self.buf.pop()
                elif ch in ("\x00", "\xe0"):
                    msvcrt.getwch()            # arrow / function keys: ignore
                elif ch == "\x1b":
                    self.buf = []
                elif ch.isprintable() and len(self.buf) < 2000:
                    self.buf.append(ch)
                self._redraw()
        return None


# ================================================================== update flow
def ask(q):
    while True:
        a = input(q + " (y/n): ").strip().lower()
        if a in ("y", "yes", "כ", "כן"):
            return True
        if a in ("n", "no", "ל", "לא"):
            return False


def handle_update(cfg, m):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(cfg["admin_pub"])).verify(
            bytes.fromhex(m["sig"]), m["payload"].encode())
        info = json.loads(m["payload"])
    except (InvalidSignature, ValueError, KeyError, TypeError):
        print("Got an update notice with a bad signature - ignored.")
        return
    if vt(info["version"]) <= vt(VERSION):
        return
    print(f"\nA new version of gocmd is required: {info['version']} (you have {VERSION}).")
    if not ask("Update now?"):
        sys.exit("gocmd closed. This version is no longer allowed - update from GitHub to use it again.")
    webbrowser.open(info["github"])
    print(f"Opened {info['github']}")
    if not ask("Do you trust the new version enough to let gocmd update itself automatically?"):
        sys.exit("gocmd closed. Update it yourself from GitHub, then run it again.")
    if not info["url"].lower().startswith("https://"):
        sys.exit("Refusing a non-HTTPS download URL.")
    data = urllib.request.urlopen(info["url"], timeout=60).read()
    if hashlib.sha256(data).hexdigest() != info["sha256"].lower():
        sys.exit("Downloaded file does not match the admin-signed hash. Update aborted.")
    target = os.path.abspath(__file__)
    tmp = target + ".new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, target)
    sys.exit(f"gocmd updated to {info['version']}. Run your command again.")


# ================================================================== chat
HELP = ("/onecode  /vote.kick.ALIAS  /vote.ALIAS  /vote.no.ALIAS  /members  /exit\n"
        "Inactive for 7 minutes = kick. Screen is wiped every 10 messages.")


def chat(conn, key, info, guard, cfg, user, address, fpr):
    """address(): current public HOST:PORT of the channel host (None if the tunnel is down)."""
    cid, me = info["cid"], info["alias"]
    ui = Console(f"=== gocmd channel | you are {me} | /help ===")
    ui.clear()
    ui.show("Members: " + ", ".join(info.get("members", [])))
    stop = threading.Event()
    state = {"reason": None, "update": None}
    pending = {}

    def receiver():
        try:
            while not stop.is_set():
                m = conn.recv()
                t = m.get("type")
                if t == "msg":
                    try:
                        text = e2e_decrypt(key, cid, m["ct"])
                    except Exception:
                        text = "<message failed authentication - dropped>"
                    ui.show(f"[{m['from']}] {text}", chat=True)
                elif t == "sys":
                    ui.show("*** " + m["text"])
                elif t == "error":
                    ui.show("!!! " + m["text"])
                elif t == "invite_ok":
                    code = pending.pop(m["lookup"], None)
                    if code:
                        ui.show(f"*** One-time code (only you see this, 3 min, single use):\n    {code}")
                        ui.show(f"*** They join with:  gocmd -u NAME -o {code}")
                elif t == "kicked":
                    state["reason"] = m["text"]
                    stop.set()
        except Exception as e:
            if not stop.is_set():
                state["reason"] = f"Disconnected: {e}"
                stop.set()

    def watchdog():
        ids = my_ids()
        next_check = time.time() + BAN_RECHECK
        while not stop.is_set():
            found = guard.scan()
            if found:
                try:
                    ban_api(cfg, "/report", {"ids": ids, "host": socket.gethostname(),
                                             "username": user, "procs": found})
                except Exception:
                    pass
                state["reason"] = ("Screen capture software detected: " + ", ".join(found) +
                                   ". You are banned for 24 hours.")
                stop.set()
                return
            try:
                guard.wipe_clipboard_images()
            except Exception:
                pass
            if time.time() >= next_check:                 # admin bans / updates reach you within a minute
                next_check = time.time() + BAN_RECHECK
                try:
                    st = ban_api(cfg, "/check", {"ids": ids, "v": VERSION})
                    if st.get("banned"):
                        state["reason"] = st.get("text", "You were banned.")
                        stop.set()
                    elif st.get("update"):
                        state["update"] = st["update"]
                        state["reason"] = "A required update was published."
                        stop.set()
                except Exception:
                    pass
            stop.wait(1.0)

    threading.Thread(target=receiver, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        while not stop.is_set():
            line = ui.readline(stop)
            if line is None:
                break
            line = line.strip()
            if not line or stop.is_set():
                continue
            low = line.lower()
            if low in ("/exit", "/quit"):
                break
            if low == "/help":
                ui.show(HELP)
            elif low == "/onecode":
                addr = address()
                if not addr:
                    ui.show("!!! The channel's tunnel is reconnecting - try again in a few seconds.")
                    continue
                secret = new_secret()
                lookup, wrap = code_material(secret)
                pending[lookup] = f"{secret}@{addr}/{fpr}"
                conn.send({"type": "invite_put", "lookup": lookup, "blob": wrap_key(wrap, key)})
            elif low == "/members":
                conn.send({"type": "members"})
            elif low.startswith("/vote.kick."):
                conn.send({"type": "vote_kick", "target": line[len("/vote.kick."):]})
            elif low.startswith("/vote.no."):
                conn.send({"type": "vote", "target": line[len("/vote.no."):], "yes": False})
            elif low.startswith("/vote."):
                conn.send({"type": "vote", "target": line[len("/vote."):], "yes": True})
            elif line.startswith("/"):
                ui.show("Unknown command. " + HELP)
            else:
                conn.send({"type": "msg", "ct": e2e_encrypt(key, cid, line)})
                ui.show(f"[{me} (you)] {line}", chat=True)
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        stop.set()
        try:
            conn.send({"type": "leave"})
        except OSError:
            pass
        for i in range(len(key)):          # best-effort wipe of the channel key
            key[i] = 0
        conn.close()
        ui.clear(show_header=False)
    print(state["reason"] or "You left the channel. It is gone for you forever.")
    if state["update"]:
        handle_update(cfg, state["update"])


# ================================================================== first run: make `gocmd` a command
SETUP_MARKER = os.path.join(HERE, ".gocmd_setup_done")


def add_to_user_path(folder, reg_key="Environment"):
    """Append folder to the per-user PATH (HKCU) if missing. Returns True if it changed."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0,
                        winreg.KEY_READ | winreg.KEY_WRITE) as k:
        try:
            cur, typ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            cur, typ = "", winreg.REG_EXPAND_SZ
        parts = [p for p in str(cur).split(";") if p.strip()]
        norm = lambda p: os.path.normcase(os.path.expandvars(p).rstrip("\\/"))
        if any(norm(p) == norm(folder) for p in parts):
            return False
        if typ not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            typ = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(k, "Path", 0, typ, ";".join(parts + [folder]))
        return True


def install_command():
    if os.name == "nt":
        bat = os.path.join(HERE, "gocmd.bat")
        if not os.path.exists(bat):
            with open(bat, "w", encoding="ascii") as f:
                f.write('@echo off\r\npython "%~dp0gocmd.py" %*\r\n')
        changed = add_to_user_path(HERE)
        if changed:
            import ctypes          # tell Windows the environment changed (new windows pick it up)
            ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 5000, None)
    else:
        bindir = os.path.expanduser("~/.local/bin")
        os.makedirs(bindir, exist_ok=True)
        launcher = os.path.join(bindir, "gocmd")
        with open(launcher, "w") as f:
            f.write(f'#!/bin/sh\nexec python3 "{os.path.join(HERE, "gocmd.py")}" "$@"\n')
        os.chmod(launcher, 0o755)
    print("Done. Open a NEW cmd window and just type:  gocmd -u NAME --new")


def first_run():
    if "--install" in sys.argv:
        install_command()
        open(SETUP_MARKER, "w").close()
        sys.exit(0)
    if os.path.exists(SETUP_MARKER) or not sys.stdin.isatty():
        return
    try:
        yes = ask("First run: make 'gocmd' a regular command, so you can type gocmd from anywhere?")
    except (EOFError, KeyboardInterrupt):
        return
    open(SETUP_MARKER, "w").close()
    if yes:
        try:
            install_command()
        except OSError as e:
            print(f"Could not add gocmd to PATH: {e}. You can retry with:  python gocmd.py --install")
    else:
        print("OK. If you change your mind:  python gocmd.py --install\n")
    if len(sys.argv) == 1:
        sys.exit(0)


# ================================================================== main
def main():
    first_run()
    p = argparse.ArgumentParser(prog="gocmd", description="Private encrypted channel chat")
    p.add_argument("-u", dest="user", required=True, help="your username (only stored with bans)")
    p.add_argument("-o", dest="code", help="one-time code to join a channel")
    p.add_argument("--new", "-new", dest="new", action="store_true", help="create a new channel")
    p.add_argument("--version", action="version", version=f"gocmd {VERSION}")
    a = p.parse_args()
    if bool(a.code) == bool(a.new):
        p.error("use exactly one of:  -o CODE  (join)   or   --new  (create)")
    cfg = load_config()
    guard = Guard(cfg)
    found = guard.scan()
    if found:
        sys.exit("Close all screen capture / recording software first: " + ", ".join(found))
    if a.code:
        try:
            secret, addr, fpr = parse_code(a.code)
            lookup, wrap = code_material(secret)
        except Exception:
            sys.exit("That is not a valid one-time code.")

    try:
        st = ban_api(cfg, "/check", {"ids": my_ids(), "v": VERSION})
    except Exception as e:
        sys.exit(f"Cannot reach the gocmd ban server ({e}). gocmd does not run without it.")
    if st.get("update"):
        handle_update(cfg, st["update"])
    if st.get("banned"):
        sys.exit(st.get("text", "You are banned."))

    host = None
    if a.new:
        print("Opening a private channel on this computer...")
        host = Host()
        if not host.start():
            sys.exit("Could not open the public tunnel (bore.pub unreachable). Try again later.")
        secret = new_secret()
        lookup, wrap = code_material(secret)
        key = bytearray(secrets.token_bytes(32))
        host.add_invite(lookup, wrap_key(wrap, key))
        server, pin_pub, pin_fpr, fpr = f"127.0.0.1:{host.port}", host.relay.pub, None, host.relay.fpr
        address = lambda: host.relay.public
    else:
        server, pin_pub, pin_fpr = addr, None, fpr
        address = lambda: addr
    try:
        conn = Conn(server, pin_pub=pin_pub, pin_fpr=pin_fpr)
        conn.send({"type": "hello", "v": VERSION})
        r = conn.recv()
        if r.get("type") != "ok":
            sys.exit("The channel does not exist anymore.")
        conn.send({"type": "join", "lookup": lookup})
        r = conn.recv()
    except (OSError, ConnectionError) as e:
        sys.exit(f"Cannot reach the channel: {e}")
    if r.get("type") != "joined":
        sys.exit(r.get("text", "Could not join."))
    if not a.new:
        try:
            key = unwrap_key(wrap, r["blob"])
        except Exception:
            sys.exit("The invite could not be decrypted.")
    chat(conn, key, r, guard, cfg, a.user, address, fpr)

    if host and not host.relay.dead and host.others():
        print(f"{host.others()} member(s) are still in the channel, and it lives on this computer.")
        print("Keep this window open to keep it alive. Close it (or Ctrl+C) to delete the channel for everyone.")
        try:
            while not host.relay.dead and host.others():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        print("Channel deleted.")


if __name__ == "__main__":
    main()
