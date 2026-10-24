"""Linux task-only controlling PTY. Synthetic password arrives on stdin only.
No browser/screen/native UI, shell wrapping, token args, or human credentials.
"""
import os,pty,termios,select,sys,time,json,signal,hashlib
from pathlib import Path
WORK_SECONDS=35
CLEANUP_SECONDS=3

def host_addresses():
 # Linux libc interface inventory, not "private IP means local".
 import ctypes,socket,ipaddress
 class Ifaddrs(ctypes.Structure):pass
 Ifaddrs._fields_=[('next',ctypes.POINTER(Ifaddrs)),('name',ctypes.c_void_p),('flags',ctypes.c_uint),('addr',ctypes.c_void_p),('netmask',ctypes.c_void_p),('union',ctypes.c_void_p),('data',ctypes.c_void_p)]
 lib=ctypes.CDLL(None,use_errno=True);head=ctypes.POINTER(Ifaddrs)()
 lib.getifaddrs.argtypes=[ctypes.POINTER(ctypes.POINTER(Ifaddrs))];lib.freeifaddrs.argtypes=[ctypes.POINTER(Ifaddrs)]
 if lib.getifaddrs(ctypes.byref(head))!=0:raise OSError(ctypes.get_errno(),'getifaddrs')
 out=set();row=head
 try:
  while row:
   addr=row.contents.addr
   if addr:
    family=ctypes.c_ushort.from_address(addr).value
    if family==socket.AF_INET:out.add(str(ipaddress.ip_address(ctypes.string_at(addr+4,4))))
    if family==socket.AF_INET6:out.add(str(ipaddress.ip_address(ctypes.string_at(addr+8,16))))
   row=row.contents.next
 finally:lib.freeifaddrs(head)
 assert out,'no concrete interface addresses'
 return out

def carrier_summary(raw,owned):
 import re,ipaddress
 text=raw.decode('utf-8',errors='strict');pairs=[]
 for line in text.splitlines():
  if 'selected pair changed:' not in line:continue
  assert '[controlled]:' in line,'unexpected ICE role in target-only private log'
  new=line.rsplit(' -> ',1)[-1]
  endpoints=re.findall(r'\b(?:udp[46]|tcp[46])\s+(host|srflx|prflx|relay)\s+([^\s]+):(\d+)\b',new)
  assert len(endpoints)==2,'selected pair endpoints not proved'
  for kind,ip,port in endpoints:
   assert kind!='relay' and 0<int(port)<=65535,'nonlocal carrier'
   assert str(ipaddress.ip_address(ip.strip('[]'))) in owned,'endpoint not on this host'
  pairs.append(endpoints)
 assert pairs,'no actual selected pair observation'
 return {'host_local_both_endpoints':True,'selected_pair_changes':len(pairs),'log_sha256':hashlib.sha256(raw).hexdigest()}

class HelperCancelled(Exception):pass

def native_login_forbidden(raw):
 # Fixed production native_auth marker is built ONLY from native-login response.status().
 # Do not accept metadata403, reflected response bodies or an incidental ID containing403.
 return b'Native authentication refused (HTTP 403 Forbidden)' in raw

def reap_owned_child(pid,budget=CLEANUP_SECONDS):
 # Signal only this unreaped child-owned group. No numeric PGID use after waitpid.
 try:os.killpg(pid,signal.SIGKILL)
 except ProcessLookupError:pass
 deadline=time.monotonic()+budget
 while time.monotonic()<deadline:
  got,status=os.waitpid(pid,os.WNOHANG)
  if got:return os.waitstatus_to_exitcode(status)
  time.sleep(.02)
 raise RuntimeError('owned PTY child not reaped within cleanup budget')

def main():
 if len(sys.argv)==4 and sys.argv[1]=='--carrier-check':
  path=Path(sys.argv[2]);offset=int(sys.argv[3]);assert 0<=offset<=path.stat().st_size<=65536
  raw=path.read_bytes();result=carrier_summary(raw[offset:],host_addresses());result['end_offset']=len(raw)
  print(json.dumps(result),flush=True);return 0
 if len(sys.argv)!=5:raise RuntimeError('fixed test-exe/case/transcript/mode required')
 exe,case_path,transcript,mode=sys.argv[1:];assert mode in ('nonce','live','reopen')
 case=json.loads(Path(case_path).read_text());assert case['mode']==mode
 password=sys.stdin.buffer.readline(4098).rstrip(b'\n');assert 0<len(password)<=4096
 assert not Path(transcript).exists()
 pid,master=pty.fork()
 if pid==0:
  os.environ['MH_NATIVE_LOGIN_CLI_CASE']=case_path
  os.environ['RUST_LOG']='off';os.environ['RUST_BACKTRACE']='0'
  os.execv(exe,[exe,'--exact','device_share_tests::native_login_cli_child','--ignored','--nocapture'])
 data=bytearray();sent=False;ready=False;status=None;end=time.monotonic()+WORK_SECONDS
 # Parent keeps this pipe open after the password; EOF is an explicit cancellation.
 def cancelled(*_):raise HelperCancelled('owned helper cancellation')
 signal.signal(signal.SIGTERM,cancelled);signal.signal(signal.SIGINT,cancelled)
 needle=('MH_NATIVE_LOGIN_'+('READY_' if mode=='live' else 'NONCE_')+case['nonce']).encode()
 def emit(x):print(json.dumps(x),flush=True)
 try:
  while time.monotonic()<end:
   if select.select([sys.stdin.fileno()],[],[],0)[0]:
    control=os.read(sys.stdin.fileno(),1)
    if not control:raise HelperCancelled('parent cancelled via EOF')
    raise HelperCancelled('unexpected control input')
   if not sent and b'MeshHarbor account password: ' in data:
    # Prompt emission may precede disabling ECHO; wait for real terminal state.
    if not termios.tcgetattr(master)[3]&termios.ECHO:
     os.write(master,password+b'\n');sent=True;emit({'event':'password-entered','echo_off':True})
   if mode=='live' and not ready and needle in data:
    ready=True;emit({'event':'remote-ready','nonce_sha256':hashlib.sha256(needle).hexdigest()})
   readable,_,_=select.select([master],[],[],.05)
   if readable:
    try:b=os.read(master,4096)
    except OSError as e:
     if e.errno==5:b=b''
     else:raise
    if b:
     data.extend(b);assert len(data)<=65536,'bounded transcript overflow'
   got,raw=os.waitpid(pid,os.WNOHANG)
   if got:
    status=os.waitstatus_to_exitcode(raw)
    # Drain kernel-buffered terminal output after actual waitpid terminal.
    drain_end=time.monotonic()+.3
    while time.monotonic()<drain_end:
     if not select.select([master],[],[],.03)[0]:continue
     try:tail=os.read(master,4096)
     except OSError as e:
      if e.errno==5:break
      raise
     if not tail:break
     data.extend(tail);assert len(data)<=65536
    break
  if status is None:raise RuntimeError('PTY child terminal timeout')
 finally:
  # Ignore a repeated cancellation while exact-owned cleanup is already underway.
  signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
  forced=status is None;reaped=False
  try:
   if forced:status=reap_owned_child(pid)
   reaped=True
  finally:
   # Evidence is private even if cleanup fails. Never print password/transcript.
   try:
    fd=os.open(transcript,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as out:out.write(data)
   finally:
    os.close(master)
    evidence={'pty_child_reaped':reaped,'pty_child_pid':pid,'forced':forced,'exit':status}
    evidence_fd=os.open(transcript+'.cleanup.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(evidence_fd,'w') as out:json.dump(evidence,out)
    if forced:emit({'event':'cleanup','pty_child_reaped':reaped,'forced':True})
 assert sent and password not in data,'terminal secrecy check failed'
 emit({'event':'terminal','exit':status,'password_absent':True,'echo_off_before_input':True,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'nonce_count':data.count(needle),'native_login_http403':native_login_forbidden(data)})
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:print(json.dumps({'event':'error','type':type(e).__name__}),flush=True);raise SystemExit(1)
