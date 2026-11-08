#!/usr/bin/env python3
"""cc3x0_decode.py ROMS_DIR OUTDIR - rebuild the 2MB memory snapshot from Glen Hewlett CC3X0 COMP####.BIN files
(searched as ROMS_DIR/rick*/COMP*.BIN). Writes rick_mem2m.bin + rick_snapshot.json (header, MMU maps, blocks)."""
import sys, glob, os, json
def segs(path):
    d=open(path,'rb').read(); i=0; out={}
    while i<len(d) and d[i]==0:
        n=(d[i+1]<<8)|d[i+2]; a=(d[i+3]<<8)|d[i+4]; out[a]=d[i+5:i+5+n]; i+=5+n
    return out
mem=bytearray(2*1024*1024); written=bytearray(len(mem)//8192)
files=sorted(glob.glob(sys.argv[1]+'/rick*/COMP*.BIN'))
hdr=None; blocks_left=None; log=[]
for f in files:
    s=segs(f); data=s[0x2000]; ctl=s[0x0F04]; size=(ctl[0]<<8)|ctl[1]
    data=data[:size]; p=0
    def byte():
        global p
        if p>=len(data): raise EOFError(f)
        b=data[p]; p+=1; return b
    def word():  # SUB_1184: big-endian
        hi=byte(); lo=byte(); return (hi<<8)|lo
    bits={'b':0,'m':0}
    def bit():
        if bits['m']==0: bits['b']=byte(); bits['m']=0x80
        r=1 if bits['b']&bits['m'] else 0; bits['m']>>=1; return r
    def gamma():
        y=1
        while not bit():
            y<<=1
            if bit(): y+=1
        return y
    if hdr is None:
        magic=bytes(byte() for _ in range(6)); assert magic==b'CC3X03',magic
        nblk=word(); w0f=word(); t0=[byte() for _ in range(8)]; t1=[byte() for _ in range(8)]
        pg23=byte(); pg24=byte(); byte(); byte(); pg25=byte(); x26=[byte() for _ in range(10)]; exe=word()
        hdr=dict(blocks=nblk,w0f=w0f,task0=[f'{x:02X}' for x in t0],task1=[f'{x:02X}' for x in t1],
                 buf23=pg23,buf24=pg24,b25=pg25,x26=bytes(x26).hex(),exec=f'{exe:04X}')
        blocks_left=nblk; print(hdr)
    while p<len(data) and blocks_left>0:
        blocks_left-=1
        page=byte(); off=word(); length=word(); extra=word()
        bits['m']=0; srcpg=None; srcoff=0
        dst=page*8192+off; start=dst; rem=length
        while rem>0:
            if bit()==0:
                n=gamma(); rem-=n
                for _ in range(n): mem[dst]=byte(); dst+=1
            else:
                newsrc=bit(); n=gamma()
                if newsrc: srcpg=byte(); srcoff=word()
                elif srcpg is None: raise ValueError('bad ref')
                src=srcpg*8192+srcoff; rem-=n
                for k in range(n): mem[dst]=mem[src+k]; dst+=1
        for pg in range(start//8192,(dst-1)//8192+1): written[pg]=1
        log.append((os.path.basename(f),page,off,length,extra))
    print(os.path.basename(f), 'flag',ctl[2], 'blocks_left',blocks_left, 'unused',len(data)-p)
out=sys.argv[2]; os.makedirs(out,exist_ok=True)
open(out+'/rick_mem2m.bin','wb').write(mem)
json.dump(dict(header=hdr,pages_written=[i for i,w in enumerate(written) if w],blocks=log),open(out+'/rick_snapshot.json','w'),indent=1)
print('pages written:',' '.join(f'{i:02X}' for i,w in enumerate(written) if w))
