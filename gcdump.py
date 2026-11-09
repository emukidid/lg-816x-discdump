"""
Fast GameCube / Wii disc dumper for HL-DT-ST GDR8162B (and compatible) drives on Windows.

Raw frames are taken straight out of the drive's sector-buffer ring with the vendor command
E7 'HIT' BB (a DMA read of buffer DRAM), instead of the 16-byte memdumps friidump/Rawdump use.
Each 16-sector ECC block costs one 1-sector streaming READ (to move the drive along) plus one
33KB BB transfer. Every frame's EDC is checked, and the scramble key is recovered from the EDC
by linearity, so there is no brute force.

  python gcdump.py E                  dump drive E: to <GAMEID>.iso (+ <GAMEID>.sha1)
  python gcdump.py E -o fifa07.iso    choose the output name
  python gcdump.py E --skip-errors    zero-fill unreadable blocks instead of stopping

Needs numpy, and usually an elevated prompt for SCSI pass-through.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import queue
import re
import sys
import threading
import time

import numpy as np

FR = 2064                   # raw frame: ID 4, IED 2, CPR_MAI 6, data 2048, EDC 4
SLOT = 16 * FR              # one ECC block
RING = 96                   # ring frames (16-frame aligned while reads stay sequential)
PSN0 = 0x30000
GC_SECTORS = 712880
WII_SL_SECTORS = 2294912
WII_DL_SECTORS = 4155840

# --- SCSI pass-through -------------------------------------------------------------------

IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014


class SPTD(ctypes.Structure):
    _fields_ = [
        ('Length', wt.USHORT), ('ScsiStatus', ctypes.c_ubyte), ('PathId', ctypes.c_ubyte),
        ('TargetId', ctypes.c_ubyte), ('Lun', ctypes.c_ubyte), ('CdbLength', ctypes.c_ubyte),
        ('SenseInfoLength', ctypes.c_ubyte), ('DataIn', ctypes.c_ubyte),
        ('DataTransferLength', wt.ULONG), ('TimeOutValue', wt.ULONG),
        ('DataBuffer', ctypes.c_void_p), ('SenseInfoOffset', wt.ULONG),
        ('Cdb', ctypes.c_ubyte * 16),
    ]


class SPTDSense(ctypes.Structure):
    _fields_ = [('sptd', SPTD), ('filler', wt.ULONG), ('sense', ctypes.c_ubyte * 32)]


k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.CreateFileW.restype = wt.HANDLE


class Drive:
    def __init__(self, letter):
        self.h = k32.CreateFileW('\\\\.\\%s:' % letter, 0xC0000000, 3, None, 3, 0, None)
        if self.h == wt.HANDLE(-1).value:
            sys.exit('cannot open drive %s: (error %d, try an elevated prompt)' % (letter, ctypes.get_last_error()))

    def cmd(self, cdb, length, timeout=10):
        buf = ctypes.create_string_buffer(length)
        s = SPTDSense()
        s.sptd.Length = ctypes.sizeof(SPTD)
        s.sptd.CdbLength = len(cdb)
        s.sptd.SenseInfoLength = 32
        s.sptd.DataIn = 1
        s.sptd.DataTransferLength = length
        s.sptd.TimeOutValue = timeout
        s.sptd.DataBuffer = ctypes.cast(buf, ctypes.c_void_p)
        s.sptd.SenseInfoOffset = SPTDSense.sense.offset
        for i, b in enumerate(cdb):
            s.sptd.Cdb[i] = b
        ret = wt.DWORD()
        if not k32.DeviceIoControl(self.h, IOCTL_SCSI_PASS_THROUGH_DIRECT, ctypes.byref(s), ctypes.sizeof(s),
                                   ctypes.byref(s), ctypes.sizeof(s), ctypes.byref(ret), None):
            return None, 'DeviceIoControl error %d' % ctypes.get_last_error()
        if s.sptd.ScsiStatus:
            sense = bytes(s.sense)
            return None, 'sense %X/%02X/%02X' % (sense[2] & 15, sense[12], sense[13])
        return buf.raw[:s.sptd.DataTransferLength], None

    def inquiry(self):
        d, e = self.cmd([0x12, 0, 0, 0, 36, 0], 36)
        return (d[8:16].decode('latin1').strip(), d[16:32].decode('latin1').strip(), d[32:36].decode('latin1')) if d else None

    def pfi(self):
        d, e = self.cmd([0xAD, 0, 0, 0, 0, 0, 0, 0, 2052 >> 8, 2052 & 255, 0, 0], 2052, timeout=30)
        return d[4:] if d else None

    def read(self, lba, n, streaming=True):
        return self.cmd([0xA8, 0, lba >> 24 & 255, lba >> 16 & 255, lba >> 8 & 255, lba & 255,
                         0, 0, n >> 8, n & 255, 0x80 if streaming else 0, 0], n * 2048, timeout=30)

    def memdump(self, addr, n):
        return self.cmd([0xE7, 0x48, 0x49, 0x54, 0x01, 0, addr >> 24 & 255, addr >> 16 & 255,
                         addr >> 8 & 255, addr & 255, n >> 8, n & 255], n, timeout=5)

    def bb(self, off, n):
        """Vendor E7 'HIT' BB: DMA read of n bytes from sector-buffer DRAM at offset off."""
        return self.cmd([0xE7, 0x48, 0x49, 0x54, 0xBB, 0, n >> 8, n & 255,
                         off >> 24 & 255, off >> 16 & 255, off >> 8 & 255, off & 255], n, timeout=5)


# --- EDC / descrambling ------------------------------------------------------------------

def _keystream(seed, n=2048):
    lfsr, out = seed, bytearray(n)
    for i in range(n):
        r = 0
        for _ in range(8):
            t = lfsr >> 14
            lfsr = ((lfsr << 1) | (t ^ ((lfsr >> 10) & 1))) & 0x7fff
            r = (r << 1) | t
        out[i] = r
    return np.frombuffer(bytes(out), np.uint8)


class Descrambler:
    """The EDC (CRC, poly 0x80000011, init 0) is linear over GF(2), so it is the XOR of a
    per-position table entry for every byte (one gather + reduce per block). The scrambler LFSR is linear too,
    so EDC(raw) ^ stored EDC == EDC(keystream) identifies the seed with one dict lookup."""

    def __init__(self):
        nbits = 2060 * 8
        r, rows = 0x80000011, []
        for _ in range(nbits):                      # rows[k] = x^(32+k) mod P
            rows.append(r)
            r = ((r << 1) ^ 0x80000011) & 0xffffffff if r & 0x80000000 else (r << 1) & 0xffffffff
        g = np.array(rows[::-1], np.uint32).reshape(2060, 8)   # bit j (MSB first) has degree nbits-1-j
        # T[pos, byte] = EDC contribution of that byte value at that position
        b = np.arange(256)
        self.T = np.zeros((2060, 256), np.uint32)
        for k in range(8):
            self.T ^= np.where(((b >> (7 - k)) & 1)[None, :] == 1, g[:, k:k + 1], np.uint32(0))
        self.pos = np.arange(2060)
        basis = [int(self.edc(np.concatenate([np.zeros((1, 12), np.uint8), _keystream(1 << i)[None]], 1))[0])
                 for i in range(15)]
        kc = [0] * 0x8000
        self.kcrc = {}
        for s in range(1, 0x8000):                  # kcrc(s) = kcrc(s without lowest bit) ^ basis[lowest bit]
            low = (s & -s).bit_length() - 1
            kc[s] = kc[s & (s - 1)] ^ basis[low]
            self.kcrc.setdefault(kc[s], s)
        self.ks = {}

    def edc(self, frames):
        """EDC of bytes 0..2059 of each frame row."""
        return np.bitwise_xor.reduce(self.T[self.pos, frames[:, :2060]], axis=1).astype(np.int64)

    def block(self, raw):
        """16 raw frames -> (16*2048 user bytes, seed), or (None, reason)."""
        f = np.frombuffer(raw, np.uint8).reshape(16, FR)
        stored = f[:, 2060:2064].astype(np.int64) @ np.array([1 << 24, 1 << 16, 1 << 8, 1], np.int64)
        seeds = {self.kcrc.get(int(k)) for k in self.edc(f) ^ stored}
        if len(seeds) != 1 or None in seeds:
            return None, 'EDC mismatch'
        seed = seeds.pop()
        if seed not in self.ks:
            self.ks[seed] = _keystream(seed)[:2042]
        # Nintendo layout: D0-D5 sit unscrambled in CPR_MAI, then 2042 scrambled bytes
        out = np.concatenate([f[:, 6:12], f[:, 12:2054] ^ self.ks[seed]], axis=1)
        return out.tobytes(), seed


# --- dumping -----------------------------------------------------------------------------

class Dumper:
    def __init__(self, drive, total, psn_for, retries):
        self.d, self.total, self.psn_for, self.retries = drive, total, psn_for, retries

    def frame_psns_ok(self, raw, lba, frames=(0, 15)):
        return all(int.from_bytes(raw[i * FR + 1:i * FR + 4], 'big') == self.psn_for(lba + i) for i in frames)

    def find(self, lba):
        """Ring frame index holding lba's first frame (frames land one by one, so after an
        unaligned read a block can start anywhere and wrap)."""
        want = self.psn_for(lba)
        for s in range(0, RING, 16):                # cheap aligned probe first
            d, e = self.d.bb(s * FR, 4)
            if d and int.from_bytes(d[1:4], 'big') == want:
                return s
        chunks = [self.d.bb(off, min(24 * FR, RING * FR - off))[0] for off in range(0, RING * FR, 24 * FR)]
        if not all(chunks):
            return None
        buf = b''.join(chunks)
        for i in range(RING):
            if int.from_bytes(buf[i * FR + 1:i * FR + 4], 'big') == want:
                return i
        return None

    def get(self, pos):
        """16 frames starting at ring frame pos, wrapping at the end of the ring."""
        n = min(16, RING - pos)
        a, e = self.d.bb(pos * FR, n * FR)
        if not a or n == 16:
            return a
        b, e = self.d.bb(0, (16 - n) * FR)
        return a + b if b else None

    def slow_read(self, lba, seek_away):
        """Full-block read of one block, optionally seeking elsewhere first so the drive
        re-reads the disc instead of handing back its cached copy. Returns (raw, slot).
        READ status is ignored: without the streaming bit the drive checks the EDC with the
        standard DVD key and fails every Nintendo sector, and either way the frames land in the
        ring, where the PSN and EDC checks decide."""
        for attempt in range(self.retries):
            if seek_away or attempt:
                far = lba + 0x4000 if lba + 0x4000 < self.total else max(0, lba - 0x4000)
                self.d.read(far, 16)
            self.d.read(lba, 16)
            slot = self.find(lba)
            if slot is None:
                continue
            raw = self.get(slot)
            if raw and self.frame_psns_ok(raw, lba, range(16)):
                return raw, slot
        return None, None

    def raw_blocks(self, stats):
        """Yield (lba, raw or None) for the whole disc, fast path with fallbacks."""
        slot, lba = None, 0
        while lba < self.total:
            raw = None
            self.d.read(lba + 15, 1)
            if slot is None:
                slot = self.find(lba)
            if slot is not None:
                raw = self.get(slot)
                if not raw or not self.frame_psns_ok(raw, lba):
                    slot = self.find(lba)
                    raw = None
                    if slot is not None:
                        raw = self.get(slot)
                        if raw and not self.frame_psns_ok(raw, lba):
                            raw = None
            if raw is None:
                stats['retries'] += 1
                raw, slot = self.slow_read(lba, seek_away=False)
            yield lba, raw
            slot = None if slot is None else (slot + 16) % RING
            lba += 16


def detect(drive, ds, dumper):
    """Read block 0 to learn the disc type; returns (sectors, header bytes)."""
    raw, _ = dumper.slow_read(0, seek_away=False)
    if raw is None:
        sys.exit('cannot read the first block of the disc')
    data, seed = ds.block(raw)
    if data is None:
        sys.exit('first block fails its EDC check: not a GameCube/Wii disc, or a bad read')
    return data


def main():
    ap = argparse.ArgumentParser(description='Fast GameCube/Wii dumper for HL-DT-ST GDR8162B-family drives')
    ap.add_argument('drive', help='drive letter, e.g. E')
    ap.add_argument('-o', '--output', help='output .iso (default <GAMEID>.iso)')
    ap.add_argument('--retries', type=int, default=8, help='re-reads per bad block (default 8)')
    ap.add_argument('--skip-errors', action='store_true', help='zero-fill unreadable blocks instead of stopping')
    ap.add_argument('--force', action='store_true', help='run on drives other than the GDR8162B')
    args = ap.parse_args()

    d = Drive(args.drive.rstrip(':'))
    inq = d.inquiry()
    if not inq:
        sys.exit('drive did not answer INQUIRY')
    print('Drive: %s %s %s' % inq)
    if not (inq[0] == 'HL-DT-ST' and inq[1].startswith('DVD-ROM GDR816')) and not args.force:
        sys.exit('only tested on HL-DT-ST DVD-ROM GDR8162B; use --force to try anyway')

    pfi = d.pfi()
    layers = ((pfi[2] >> 5) & 3) + 1 if pfi else 1
    end0 = int.from_bytes(pfi[13:16], 'big') if pfi else 0

    def psn_for(lba):
        if layers == 2 and end0 and lba > end0 - PSN0:     # opposite track path: layer 1 counts up from ~end0
            return ((~end0) & 0xffffff) + lba - (end0 - PSN0 + 1)
        return PSN0 + lba

    print('Building EDC tables...', end='', flush=True)
    ds = Descrambler()
    print(' done')

    # make sure BB really reads the sector buffer on this drive before trusting it
    d.read(0, 1)
    a, e1 = d.memdump(0x80000000, 16)
    b, e2 = d.bb(0, 16)
    if e1 or e2 or a != b:
        sys.exit('drive does not support the buffer read (E7 HIT BB): %s' % (e1 or e2 or 'data differs'))

    probe = Dumper(d, GC_SECTORS, psn_for, args.retries)
    hdr = detect(d, ds, probe)
    if hdr[0x1C:0x20] == b'\xc2\x33\x9f\x3d':
        kind, total = 'GameCube', GC_SECTORS
    elif hdr[0x18:0x1C] == b'\x5d\x1c\x9e\xa3':
        kind, total = ('Wii dual layer', WII_DL_SECTORS) if layers == 2 else ('Wii', WII_SL_SECTORS)
    else:
        sys.exit('unrecognised disc header (no GameCube or Wii magic)')
    gid = hdr[:6].decode('latin1')
    title = hdr[0x20:0x60].split(b'\0')[0].decode('latin1', 'replace')
    disc = hdr[6]
    print('Disc: %s  %s  "%s"%s  version %d  %d sectors (%.2f GB)'
          % (kind, gid, title, '  disc %d' % (disc + 1) if disc else '', hdr[7], total, total * 2048 / 1e9))
    if layers == 2:
        print('Note: dual-layer LBA mapping is untested on this drive')

    out = args.output or re.sub(r'[^\w.-]', '_', gid + ('_disc%d' % (disc + 1) if disc else '')) + '.iso'
    shaf = os.path.splitext(out)[0] + '.sha1'
    dumper = Dumper(d, total, psn_for, args.retries)
    stats = {'retries': 0, 'edc': 0, 'edc_run': 0}
    failed, zeroed = [], []
    q = queue.Queue(maxsize=256)
    sha = hashlib.sha1()
    werr = []

    def worker(f):
        try:
            while True:
                item = q.get()
                if item is None:
                    return
                lba, raw = item
                data = None
                if raw is not None:
                    data, _ = ds.block(raw)
                    if data is None:
                        stats['edc'] += 1
                        stats['edc_run'] += 1
                    else:
                        stats['edc_run'] = 0
                if data is None:
                    failed.append(lba)
                    data = bytes(SLOT // FR * 2048)
                f.write(data)
                if not failed:
                    sha.update(data)
        except Exception as ex:
            werr.append(ex)

    t0 = time.time()
    last = 0
    with open(out, 'wb') as f:
        th = threading.Thread(target=worker, args=(f,), daemon=True)
        th.start()
        try:
            for lba, raw in dumper.raw_blocks(stats):
                if werr:
                    raise werr[0]
                # health: the first GDR8162B died with steadily rising EDC failures, then stopped
                # answering INQUIRY, so stop early rather than keep hammering a failing drive
                if (lba >> 4) % 512 == 0 and lba and not d.inquiry():
                    raise RuntimeError('drive stopped answering INQUIRY at LBA 0x%X' % lba)
                if stats['edc_run'] >= 4 or stats['edc'] > 32:
                    raise RuntimeError('EDC failures rising (%d total, %d in a row) at LBA 0x%X: stopping to protect the drive'
                                       % (stats['edc'], stats['edc_run'], lba))
                if raw is None and not args.skip_errors:
                    raise RuntimeError('block at LBA 0x%X unreadable after %d tries (use --skip-errors to continue)'
                                       % (lba, args.retries))
                q.put((lba, raw))
                now = time.time()
                if now - last > 0.5 or lba + 16 >= total:
                    last = now
                    done = lba + 16
                    rate = done * 2048 / (now - t0)
                    eta = (total - done) * 2048 / rate if rate else 0
                    print('\r  %5.1f%%  LBA %07X/%07X  %5.2f MB/s  ETA %d:%02d  retries %d  bad %d '
                          % (done * 100 / total, done, total, rate / 1e6, eta // 60, eta % 60,
                             stats['retries'], len(failed)), end='', flush=True)
        except KeyboardInterrupt:
            q.put(None)
            th.join()
            sys.exit('\ninterrupted; %s is incomplete' % out)
        except RuntimeError as ex:
            q.put(None)
            th.join()
            sys.exit('\n%s; %s is incomplete' % (ex, out))
        q.put(None)
        th.join()
        if werr:
            raise werr[0]
        print()

        # blocks that failed EDC (or reads) get re-read from the disc after seeking away
        for lba in list(failed):
            data = None
            for _ in range(2):
                raw, _ = dumper.slow_read(lba, seek_away=True)
                if raw is not None:
                    data, _ = ds.block(raw)
                    if data is not None:
                        break
            if data is None:
                zeroed.append(lba)
                if not args.skip_errors:
                    sys.exit('block at LBA 0x%X keeps failing its EDC check; %s is incomplete' % lba)
                continue
            f.seek(lba * 2048)
            f.write(data)
            print('  recovered block at LBA 0x%X' % lba)

    if failed:      # the running hash stopped at the first bad block; hash the finished file
        sha = hashlib.sha1()
        with open(out, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 22), b''):
                sha.update(chunk)
    digest = sha.hexdigest()
    with open(shaf, 'w', newline='\n') as f:
        f.write('%s *%s\n' % (digest, os.path.basename(out)))
    dt = time.time() - t0
    print('Done in %d:%02d (%.2f MB/s), %d slow re-reads, %d EDC re-reads'
          % (dt // 60, dt % 60, total * 2048 / dt / 1e6, stats['retries'], stats['edc']))
    if zeroed:
        print('WARNING: %d block(s) zero-filled, the dump is NOT good: %s'
              % (len(zeroed), ' '.join('0x%X' % l for l in zeroed)))
    print('SHA-1: %s  (%s)' % (digest, shaf))


if __name__ == '__main__':
    main()
