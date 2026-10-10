"""MP3 structure audit and spectrogram using installed mpg123 (no input execution).
Run using bundled Python for numpy/Pillow. No dependencies downloaded.
"""
from pathlib import Path
import collections, ctypes as C, hashlib, json, math, struct
import numpy as np
from PIL import Image, ImageDraw
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'output/iso-audit'
b=(OUT/'iso-files/AUDIO/761.MP3').read_bytes()
def synchsafe(x):
    if any(c&128 for c in x):raise ValueError('Invalid synchsafe integer')
    return sum(c << (7*(len(x)-i-1)) for i,c in enumerate(x))
assert b[:3]==b'ID3'
version=b[3]; tagend=10+synchsafe(b[6:10]); pos=10;tags=[]
while pos+10<=tagend and b[pos]:
    ident=b[pos:pos+4].decode('ascii');size=(synchsafe(b[pos+4:pos+8]) if version==4 else int.from_bytes(b[pos+4:pos+8],'big'))
    payload=b[pos+10:pos+10+size]
    assert pos+10+size<=tagend
    enc={0:'latin1',1:'utf-16',2:'utf-16-be',3:'utf-8'}.get(payload[0],'latin1')
    tags.append({'id':ident,'size':size,'flags_hex':b[pos+8:pos+10].hex(),'text':payload[1:].decode(enc,'replace'),'payload_hex':payload.hex()})
    pos+=10+size
tag_padding_nonzero=sum(x!=0 for x in b[pos:tagend])
frames=[];errors=[]; pos=tagend;bitrate_table=[0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0]
end=len(b)-128 if b[-128:-125]==b'TAG' else len(b)
while pos+4<=end:
    h=int.from_bytes(b[pos:pos+4],'big')
    if h>>21!=0x7ff or (h>>19)&3!=3 or (h>>17)&3!=1:
        errors.append({'offset':pos,'reason':'not MPEG1 layer3 header'});break
    bitrate=bitrate_table[(h>>12)&15]; sr=[44100,48000,32000,0][(h>>10)&3]
    if not bitrate or not sr:errors.append({'offset':pos,'reason':'invalid rate'});break
    padding=(h>>9)&1;size=144000*bitrate//sr+padding
    if pos+size>end:errors.append({'offset':pos,'reason':'truncated frame'});break
    frames.append({'offset':pos,'size':size,'bitrate':bitrate,'sample_rate':sr,'padding':padding,
                   'private_bit':(h>>8)&1,'channel_mode':(h>>6)&3,'copyright':(h>>3)&1,'original':(h>>2)&1,'emphasis':h&3})
    pos+=size
result={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'id3_version':version,
        'id3_total_size':tagend,'id3_frames':tags,'id3_padding_nonzero':tag_padding_nonzero,
        'mpeg_frames':len(frames),'stream_end':pos,'unparsed_size':end-pos,'errors':errors,
        'id3v1_hex':b[-128:].hex() if end<len(b) else None,
        'header_distributions':{k:dict(collections.Counter(f[k] for f in frames)) for k in frames[0] if k not in ('offset','size')},
        'mpeg_duration_including_info_frame':len(frames)*1152/frames[0]['sample_rate']}
first=b[frames[0]['offset']:frames[0]['offset']+frames[0]['size']]
result['first_frame_hex']=first.hex()
result['padding_49_frame_period_mismatches_excluding_info']=sum(frames[i]['padding']!=frames[i+49]['padding'] for i in range(1,len(frames)-49))
info=first.find(b'Info')
if info<0:info=first.find(b'Xing')
if info>=0:
    flags=int.from_bytes(first[info+4:info+8],'big'); p=info+8
    xing={'marker':first[info:info+4].decode(),'flags':flags}
    for flag,name,length in [(1,'frames',4),(2,'bytes',4),(4,'toc',100),(8,'quality',4)]:
        if flags&flag:
            xing[name]=first[p:p+length].hex() if flag==4 else int.from_bytes(first[p:p+length],'big');p+=length
    xing['encoder']=first[p:p+9].decode('ascii','replace')
    crc_table=[]
    for value in range(256):
        c=value
        for _ in range(8):c=(c>>1)^0xa001 if c&1 else c>>1
        crc_table.append(c)
    def lame_crc16(blob):
        c=0
        for value in blob:c=(c>>8)^crc_table[(c^value)&255]
        return c
    music_stored=int.from_bytes(first[p+32:p+34],'big')
    tag_stored=int.from_bytes(first[p+34:p+36],'big')
    music_computed=lame_crc16(b[frames[1]['offset']:end])
    tag_computed=lame_crc16(first[:p+34])
    xing.update({'music_crc16_stored':hex(music_stored),'music_crc16_computed':hex(music_computed),
        'music_crc16_valid':music_stored==music_computed,'tag_crc16_stored':hex(tag_stored),
        'tag_crc16_computed':hex(tag_computed),'tag_crc16_valid':tag_stored==tag_computed,
        'info_frame_filler_nonzero':sum(x!=0 for x in first[p+36:]),
        'crc_source':'https://github.com/lameproject/lame/blob/master/libmp3lame/VbrTag.c',
        'crc_caveat':'Transport/encoder consistency checks, not cryptographic authentication and not a complete MP3 steganography test.'})
    delay=int.from_bytes(first[p+21:p+24],'big');xing['encoder_delay']=delay>>12;xing['encoder_padding']=delay&4095
    if 'frames' in xing:
        xing['duration_without_encoder_delay_padding']=(xing['frames']*1152-xing['encoder_delay']-xing['encoder_padding'])/44100
    result['xing_lame']=xing

library=Path('C:/Program Files/Audacity/mpg123.dll')
lib=C.CDLL(str(library))
lib.mpg123_new.argtypes=[C.c_char_p,C.POINTER(C.c_int)];lib.mpg123_new.restype=C.c_void_p
lib.mpg123_open.argtypes=[C.c_void_p,C.c_char_p];lib.mpg123_open.restype=C.c_int
lib.mpg123_getformat.argtypes=[C.c_void_p,C.POINTER(C.c_long),C.POINTER(C.c_int),C.POINTER(C.c_int)]
lib.mpg123_format_none.argtypes=[C.c_void_p]
lib.mpg123_format.argtypes=[C.c_void_p,C.c_long,C.c_int,C.c_int]
lib.mpg123_read.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)];lib.mpg123_read.restype=C.c_int
lib.mpg123_delete.argtypes=[C.c_void_p];lib.mpg123_close.argtypes=[C.c_void_p]
lib.mpg123_init()
err=C.c_int(); handle=lib.mpg123_new(None,C.byref(err))
if not handle: result['decode_error']='mpg123_new failed: '+str(err.value)
else:
    try:
        assert lib.mpg123_format_none(handle)==0
        assert lib.mpg123_format(handle,44100,2,0x200)==0
        assert lib.mpg123_open(handle,str(OUT/'iso-files/AUDIO/761.MP3').encode())==0
        rate=C.c_long();channels=C.c_int();encoding=C.c_int()
        assert lib.mpg123_getformat(handle,C.byref(rate),C.byref(channels),C.byref(encoding))==0
        assert rate.value==44100 and channels.value==2 and encoding.value==0x200
        buf=C.create_string_buffer(1024*1024); done=C.c_size_t();chunks=[];total=0
        while True:
            status=lib.mpg123_read(handle,buf,len(buf),C.byref(done))
            if done.value:chunks.append(buf.raw[:done.value]);total+=done.value
            assert total<44100*600*2*4
            if status==-12:break
            if status!=0:raise ValueError('mpg123_read status '+str(status))
        pcm=np.frombuffer(b''.join(chunks),dtype=np.float32).reshape(-1,2);read=len(pcm)
        result['decoded']={'library':str(library),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'samples_per_channel':read,'channels':2,'sample_rate':44100,'duration':read/44100,
            'peak':float(np.abs(pcm).max()),'channel_correlation':float(np.corrcoef(pcm.T)[0,1])}
        tone_fft=65536;tone_hz=np.fft.rfftfreq(tone_fft,1/44100);mask=(tone_hz>=15400)&(tone_hz<=16100)
        carrier=[];mono=pcm.mean(axis=1);tone_window=np.hanning(tone_fft)
        for start in range(0,len(mono)-tone_fft,22050):
            magnitudes=np.abs(np.fft.rfft(mono[start:start+tone_fft]*tone_window))[mask]
            which=int(magnitudes.argmax())
            carrier.append({'time_s':start/44100,'peak_hz':float(tone_hz[mask][which]),'peak_magnitude':float(magnitudes[which])})
        result['high_tone_tracking']=carrier
        result['high_tone_peak_hz_range']=[min(x['peak_hz'] for x in carrier),max(x['peak_hz'] for x in carrier)]
        # Spectra for L, R, mid and side. Preserve numeric data and readable previews.
        signals={'left':pcm[:,0],'right':pcm[:,-1],'mid':pcm.mean(axis=1),'side':(pcm[:,0]-pcm[:,-1])/2}
        fftsize=4096;hop=2205;window=np.hanning(fftsize).astype(np.float32)
        ntime=(read-fftsize)//hop+1
        spectral={}
        for name,s in signals.items():
            spectrum=np.empty((fftsize//2+1,ntime),np.float32)
            for j in range(ntime):spectrum[:,j]=np.abs(np.fft.rfft(s[j*hop:j*hop+fftsize]*window))
            db=20*np.log10(np.maximum(spectrum,1e-9));spectral[name]=db
            # 0..22.05kHz, fixed log intensity scaled relative to strongest bin.
            norm=np.clip((db-db.max()+85)/85,0,1)
            rgb=np.stack([np.clip(norm*2,0,1),np.clip(norm*2-0.6,0,1),np.clip(norm*3-2,0,1)],axis=-1)
            im=Image.fromarray((rgb[::-1]*255).astype(np.uint8)).resize((1200,500))
            canvas=Image.new('RGB',(1300,590),'white');canvas.paste(im,(70,40));draw=ImageDraw.Draw(canvas)
            draw.text((70,10),f'761.mp3 — {name} | 4096-point Hann FFT | relative dB (-85..0)',fill='black')
            for hz in (0,5000,10000,15000,20000):
                y=540-int(hz/22050*500);draw.text((5,y-5),str(hz)+' Hz',fill='black')
            for sec in range(0,167,20):
                x=70+int(sec/(read/44100)*1200);draw.text((x,550),str(sec)+' s',fill='black')
            canvas.save(OUT/f'audio-spectrogram-{name}.png')
        np.savez_compressed(OUT/'audio-spectral-data.npz',**spectral,fft_size=fftsize,hop=hop,sample_rate=44100)
        hz=np.fft.rfftfreq(fftsize,1/44100)
        band=(hz>=15400)&(hz<=16100)
        avg=np.mean(10**(spectral['mid']/10),axis=1)
        peaks=np.argsort(avg[band])[-10:][::-1];bhz=hz[band]
        result['high_band_peaks_hz']=[float(bhz[x]) for x in peaks]
        result['spectrogram_caveat']='Visual screening only; not exhaustive steganalysis or a reliable musical-key/tempo/transcription result.'
    except Exception as exc:result['decode_error']=repr(exc)
    finally:lib.mpg123_close(handle);lib.mpg123_delete(handle);lib.mpg123_exit()
(OUT/'audio-audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:result[k] for k in ('mpeg_frames','unparsed_size','errors','xing_lame') if k in result},indent=2))
print(json.dumps(result.get('decoded',result.get('decode_error')),indent=2))
