# What is it?

A python script that dumps GameCube and Wii discs on Windows using an HL-DT-ST (LG) GDR8162B DVD-ROM drive. (8161/8163/8164 haven't been tested). No custom firmware is needed.

It's faster than friidump/Rawdump because raw frames are taken straight out of the drive's sector-buffer ring with the vendor command E7 'HIT' BB (a DMA read of buffer DRAM), instead of the 16-byte memdumps friidump/Rawdump use.

It writes a `.iso` and a `.sha1` file next to it. There's no BCA dumping support.

Most of this was written with LLM assistance, I have verified a bunch of disc dumps myself, use it with caution, I take no responsibility for any issues that might arise from using it.

## Requirements

- Windows
- Python 3 (64-bit)
- numpy:

  ```
  pip install numpy
  ```

- An HL-DT-ST DVD-ROM GDR8162B. This is the only drive it has been tested on. Other GDR816x models may work.
- Run it from an Administrator command prompt if it says it can't open the drive.

## Usage

Put the disc in the drive, then from this folder run:

```
python gcdump.py E
```

`E` is the drive letter. The output is named after the game ID, for example `G4FP69.iso` and `G4FP69.sha1`.

Options:

```
python gcdump.py E -o mygame.iso    choose the output file name
python gcdump.py E --skip-errors    zero-fill unreadable blocks instead of stopping
python gcdump.py E --retries 16     re-read bad blocks more times (default 8)
```

## What to expect

- A GameCube disc (1.4 GB) takes about 5 minutes. A single-layer Wii disc (4.7 GB) takes about 22 minutes.
- A few "EDC re-reads" are normal. Those blocks are read again at the end of the dump.
- The dumper stops on its own if the drive stops responding or read errors keep climbing. That protects the drive. Check the drive and its USB enclosure or power before trying again.
- Compare the hash in the `.sha1` file with the redump.org entry for the game to confirm the dump is good.
- Dual-layer Wii discs are untested.
