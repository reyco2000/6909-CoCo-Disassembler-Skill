#!/usr/bin/env python3
"""decb_extract.py IMAGE.DSK OUTDIR - extract all files from a 35-track RS-DOS (DECB) disk image.
Directory: track 17 sectors 3-11; FAT: track 17 sector 2; 68 granules of 9 sectors."""
import sys, os
def sec(img, t, s): o=(t*18+s-1)*256; return img[o:o+256]
img=open(sys.argv[1],'rb').read(); out=sys.argv[2]; os.makedirs(out,exist_ok=True)
fat=sec(img,17,2)[:68]
types={0:'BASIC',1:'DATA',2:'ML',3:'TEXT'}
for s in range(3,12):
    d=sec(img,17,s)
    for i in range(8):
        e=d[i*32:i*32+32]
        if e[0]==0: continue
        if e[0]==0xFF: break
        name=e[0:8].decode('latin1').rstrip(); ext=e[8:11].decode('latin1').rstrip()
        ftype=e[11]; asc=e[12]; g=e[13]; last=(e[14]<<8)|e[15]
        data=b''; n=0
        while True:
            nx=fat[g]; tr=g//2 if g<34 else g//2+1; s0=1+(g%2)*9
            gran=b''.join(sec(img,tr,s0+k) for k in range(9))
            if nx>=0xC0:
                ns=nx&0x1F; data+=gran[:(ns-1)*256+last] if ns else b''; break
            data+=gran; g=nx; n+=1
            if n>80: break
        fn=f"{name}.{ext}"; open(os.path.join(out,fn),'wb').write(data)
        print(f"{fn:14} type={types.get(ftype,ftype)} {'ASCII' if asc else 'BIN'} size={len(data)}")
