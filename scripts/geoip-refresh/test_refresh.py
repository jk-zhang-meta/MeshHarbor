#!/usr/bin/env python3
"""Local failure/recovery oracle; only stub Docker/curl, no daemon/network."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FETCH = HERE.parent / 'fetch-geoip.sh'
DB = 'dbip-country-lite.mmdb'
PROV = 'dbip-country-lite.provenance.txt'
IMAGE = 'sha256:' + '1' * 64
APP = '2' * 64

MOCK = r'''#!/usr/bin/env python3
import gzip,json,os,pathlib,subprocess,sys
r=pathlib.Path(os.environ['MOCK_ROOT']); s=json.loads((r/'state').read_text()); a=sys.argv[1:]
name=pathlib.Path(sys.argv[0]).name
def save(): (r/'state').write_text(json.dumps(s))
if name=='mv':
 if s['case']=='switch-failure' and a[-1]==str(r/'data/current'):
  sys.exit(28)
 sys.exit(subprocess.run(['/usr/bin/mv',*a]).returncode)
if name=='sleep': sys.exit(0)
if name=='curl':
 if '-o' in a:
  if s['case']=='no-file': sys.exit(22)
  pathlib.Path(a[a.index('-o')+1]).write_bytes(gzip.compress((r/'download').read_bytes())); sys.exit(0)
 sys.exit(0 if s['restarts']!=1 or s['case'] not in ('rollback','rollback-failure') else 22)
if a[0]=='inspect':
 if '--format' in a:
  print('unhealthy' if s['case'] in ('rollback','rollback-failure') and s['restarts']==1 else 'healthy'); sys.exit(0)
 s['inspections']+=1; save()
 started='initial' if not s['restarts'] else 'restart-'+str(s['restarts'])
 if s['case']=='restart-noop' and s['restarts']==1: started='initial'
 if s['case']=='drift' and s['inspections']>=2: started='other-deploy'
 source=str(r/'data') if s['case']!='wrong-mount' else '/wrong'
 env=['MESHHARBOR__STATS__GEOIP_MMDB=/usr/share/roomler/geoip-managed/current/dbip-country-lite.mmdb']
 if s['case']=='env-drift' and s['inspections']>=2: env=[]
 image='sha256:'+('3' if s['case']=='image-drift' and s['inspections']>=2 else '1')*64
 running=not(s['case']=='stopped-restart-failure' and s['restarts']==1)
 print(json.dumps([{'Id':'2'*64,'Image':image,'State':{'Running':running,'StartedAt':started},'Mounts':[{'Type':'bind','Source':source,'Destination':'/usr/share/roomler/geoip-managed','RW':False}],'Config':{'Env':env}}])); sys.exit(0)
if a[0]=='run':
 for seq in [['--rm'],['--network','none'],['--read-only'],['--cap-drop','ALL'],['--security-opt','no-new-privileges'],['--user','65534:65534'],['--memory','128m'],['--cpus','0.5'],['--pids-limit','32'],['--entrypoint','/usr/local/bin/meshharbor-geoip-check']]:
  assert any(a[i:i+len(seq)]==seq for i in range(len(a)))
 assert a[-2]=='sha256:'+'1'*64 and a[-1]=='/candidate/dbip-country-lite.mmdb'
 mount=a[a.index('--mount')+1]; assert mount.startswith('type=bind,src=') and mount.endswith(',dst=/candidate,readonly')
 p=pathlib.Path(mount.split('src=',1)[1].split(',dst=')[0])/'dbip-country-lite.mmdb'
 assert p.is_file()
 if s['case']=='empty-json': print('{}'); sys.exit(0)
 valid=s['case']!='invalid'
 epoch=int(p.read_bytes().split(b'\n',1)[0])
 print(json.dumps({'valid':valid,'status':'current' if valid else 'invalid','database_type':'DBIP-Country-Lite','build_epoch':epoch,'age_secs':0,'max_age_secs':120*86400}))
 sys.exit(0 if valid else 1)
if a[0]=='restart':
 assert a[1]=='2'*64
 s['restarts']+=1; save()
 sys.exit(17 if s['case'] in ('restart-failure','stopped-restart-failure') and s['restarts']==1 else 23 if s['case']=='rollback-failure' and s['restarts']==2 else 0)
raise AssertionError(a)
'''


def dataset(epoch, salt):
    return str(epoch).encode() + b'\n' + salt.encode() + b'x' * (1024 * 1024) + b'\xab\xcd\xefMaxMind.com DBIP-Country-Lite'


class Refresh(unittest.TestCase):
    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='geoip-refresh-oracle-') as raw:
            root = Path(raw)
            (root / 'bin').mkdir()
            for name in ('docker', 'curl', 'sleep', 'mv'):
                f = root / 'bin' / name
                f.write_text(MOCK)
                f.chmod(0o755)
            data = root / 'data'
            releases = data / 'releases'
            releases.mkdir(parents=True)
            unrelated = data / '.candidate.unrelated'
            unrelated.mkdir()
            (unrelated / 'keep').write_text('another operation owns this\n')
            old = dataset(100, 'old')
            new = old if case == 'same' else dataset(99 if case == 'downgrade' else 200, 'new')
            old_digest = hashlib.sha256(old).hexdigest()
            old_rel = 'releases/' + old_digest
            bundle = data / old_rel
            bundle.mkdir()
            (bundle / DB).write_bytes(old)
            (bundle / 'build_epoch').write_text('100\n')
            if case == 'missing-manifest':
                (bundle / 'build_epoch').unlink()
            (bundle / PROV).write_text('existing accepted release\n')
            (data / 'current').symlink_to(old_rel)
            (root / 'download').write_bytes(new)
            (root / 'state').write_text(json.dumps({'case': case, 'restarts': 0, 'inspections': 0}))
            fetch = root / 'fetch-geoip.sh'
            shutil.copyfile(FETCH, fetch)
            fetch.chmod(0o755)
            config = root / 'config'
            config.write_text(f'DATA_ROOT={data}\nCONTAINER=meshharbor-test-app-1\nREADY_URL=http://127.0.0.1:18081/health/ready\nFETCH_SCRIPT={fetch}\nLOCK_FILE={root}/app.lock\n')
            config.chmod(0o600)
            if case == 'bad-config':
                config.write_text(config.read_text() + 'UNRECOGNIZED=ignored\n')
            env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], MOCK_ROOT=str(root))
            result = subprocess.run(['bash', str(HERE / 'refresh.sh'), '--config', str(config)], env=env, capture_output=True, text=True, timeout=15)
            state = json.loads((root / 'state').read_text())
            target = os.readlink(data / 'current')
            self.assertEqual([p.name for p in data.glob('.candidate.*')], ['.candidate.unrelated'])
            self.assertTrue((unrelated / 'keep').is_file())
            self.assertEqual((bundle / DB).read_bytes(), old)
            if case in ('same', 'changed'):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(state['restarts'], 0 if case == 'same' else 1)
                expected = hashlib.sha256(new).hexdigest()
                self.assertEqual(target, 'releases/' + expected)
                self.assertEqual((data / target / DB).read_bytes(), new)
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(target, old_rel, result.stderr)
                recovery = ('rollback', 'restart-failure', 'restart-noop', 'stopped-restart-failure', 'rollback-failure')
                self.assertEqual(state['restarts'], 2 if case in recovery else 0, result.stderr)
                if case in recovery and case != 'rollback-failure':
                    self.assertIn('rollback verified', result.stderr)
                if case == 'rollback-failure':
                    self.assertIn('CRITICAL rollback could not be verified', result.stderr)
                if case == 'switch-failure':
                    self.assertIn('activation was not committed', result.stderr)
                    self.assertNotIn('CRITICAL', result.stderr)
            if case in ('changed', 'rollback', 'restart-failure', 'restart-noop', 'stopped-restart-failure', 'rollback-failure', 'switch-failure'):
                self.assertEqual((releases / hashlib.sha256(new).hexdigest() / DB).read_bytes(), new)
            return case, result.returncode, state['restarts']

    def test_scenarios(self):
        for case in ('same', 'changed', 'no-file', 'invalid', 'empty-json', 'downgrade', 'drift', 'image-drift', 'env-drift', 'wrong-mount', 'bad-config', 'missing-manifest', 'rollback', 'restart-failure', 'restart-noop', 'stopped-restart-failure', 'rollback-failure', 'switch-failure'):
            with self.subTest(case=case):
                print('OBSERVED', self.run_case(case), flush=True)


if __name__ == '__main__':
    unittest.main()
