#!/usr/bin/env python3
from __future__ import annotations
import argparse
import collections
import csv
import dataclasses
import datetime
import fnmatch
import json
import math
import os
import pathlib
import re
import signal
import socket
import statistics
import sys
import time
from typing import Any

VERSION = '1.0.0'
RUNNING = True
POLICIES = {0:'OTHER',1:'FIFO',2:'RR',3:'BATCH',5:'IDLE',6:'DEADLINE',7:'EXT'}
COLORS = {'reset':'\033[0m','purple':'\033[38;5;141m','violet':'\033[38;5;99m','cyan':'\033[38;5;51m','blue':'\033[38;5;75m','green':'\033[38;5;84m','yellow':'\033[38;5;220m','red':'\033[38;5;203m','dim':'\033[38;5;245m','white':'\033[38;5;255m'}

def stop(sig, frame):
    global RUNNING
    RUNNING = False

def read(path, limit=1048576):
    try:
        with open(path,'r',encoding='utf-8',errors='replace') as f:
            return f.read(limit)
    except (OSError,UnicodeError):
        return ''

def number(value, default=0):
    try:
        return int(value)
    except (ValueError,TypeError,OverflowError):
        return default

def decimal(value, default=0.0):
    try:
        result=float(value)
        return result if math.isfinite(result) else default
    except (ValueError,TypeError,OverflowError):
        return default

def utc(ts=None):
    return datetime.datetime.fromtimestamp(time.time() if ts is None else ts,datetime.timezone.utc).isoformat()

def ratio(a,b):
    return 100.0*a/b if b>0 else 0.0

def diff(a,b):
    return max(0,a-b)

def human_ns(value):
    if value>=1e9: return f'{value/1e9:.3f}s'
    if value>=1e6: return f'{value/1e6:.3f}ms'
    if value>=1e3: return f'{value/1e3:.3f}us'
    return f'{value:.0f}ns'

def write_json(path,data):
    target=pathlib.Path(path)
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_name('.'+target.name+'.'+str(os.getpid())+'.tmp')
    try:
        with tmp.open('w',encoding='utf-8') as stream:
            json.dump(data,stream,indent=2,allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,target)
    finally:
        if tmp.exists(): tmp.unlink()

def load_json(path,max_bytes=64*1024*1024):
    p=pathlib.Path(path)
    if p.stat().st_size>max_bytes: raise ValueError('snapshot exceeds maximum size')
    with p.open(encoding='utf-8') as f:
        obj=json.load(f)
    if not isinstance(obj,dict): raise ValueError('snapshot must be a JSON object')
    return obj

def status_fields(pid,tid):
    raw=read(f'/proc/{pid}/task/{tid}/status',65536)
    fields={}
    for line in raw.splitlines():
        if ':' in line:
            k,v=line.split(':',1)
            fields[k]=v.strip()
    return fields

def parse_stat(pid,tid):
    raw=read(f'/proc/{pid}/task/{tid}/stat',16384).strip()
    left=raw.find('(')
    right=raw.rfind(')')
    if left<0 or right<left: return None
    values=raw[right+1:].strip().split()
    if len(values)<40: return None
    return {'comm':raw[left+1:right],'state':values[0],'ppid':number(values[1]),'utime':number(values[11]),'stime':number(values[12]),'priority':number(values[15]),'nice':number(values[16]),'threads':number(values[17]),'starttime':number(values[19]),'processor':number(values[36]),'policy':number(values[38]),'delayacct_ticks':number(values[39])}

def schedstat(pid,tid):
    values=read(f'/proc/{pid}/task/{tid}/schedstat',256).split()
    return {'runtime_ns':number(values[0]) if len(values)>0 else None,'wait_ns':number(values[1]) if len(values)>1 else None,'timeslices':number(values[2]) if len(values)>2 else None}

def sched_extra(pid,tid):
    raw=read(f'/proc/{pid}/task/{tid}/sched',131072)
    result={}
    keys={'se.sum_exec_runtime':'sum_exec_runtime_ms','se.vruntime':'vruntime','nr_switches':'nr_switches','nr_migrations':'nr_migrations','se.statistics.wait_sum':'wait_sum_ms','se.statistics.wait_max':'wait_max_ms','se.statistics.iowait_sum':'iowait_sum_ms','se.statistics.sleep_max':'sleep_max_ms','se.avg.util_avg':'util_avg','se.avg.load_avg':'load_avg','se.avg.runnable_avg':'runnable_avg'}
    for line in raw.splitlines():
        if ':' not in line: continue
        k,v=line.split(':',1)
        k=k.strip()
        if k in keys: result[keys[k]]=decimal(v.strip().split()[0]) if v.strip() else 0.0
    return result

def affinity(pid,tid):
    try:
        return sorted(os.sched_getaffinity(tid))
    except (OSError,AttributeError):
        value=status_fields(pid,tid).get('Cpus_allowed_list','')
        return value

def read_psi(resource):
    data={}
    for line in read(f'/proc/pressure/{resource}',8192).splitlines():
        tokens=line.split()
        if not tokens: continue
        values={}
        for token in tokens[1:]:
            if '=' in token:
                k,v=token.split('=',1)
                values[k]=number(v) if k=='total' else decimal(v)
        data[tokens[0]]=values
    return data

def cpu_stat():
    data={}
    for line in read('/proc/stat',262144).splitlines():
        p=line.split()
        if p and p[0].startswith('cpu') and (p[0]=='cpu' or p[0][3:].isdigit()):
            data[p[0]]=[number(v) for v in p[1:]]
    return data

def sched_system():
    data={}
    for line in read('/proc/schedstat',1048576).splitlines():
        p=line.split()
        if p and re.fullmatch(r'cpu\d+',p[0]):
            data[p[0]]=[number(v) for v in p[1:]]
    return data

def loadavg():
    p=read('/proc/loadavg',256).split()
    return {'load1':decimal(p[0]) if len(p)>0 else 0,'load5':decimal(p[1]) if len(p)>1 else 0,'load15':decimal(p[2]) if len(p)>2 else 0,'running':p[3] if len(p)>3 else ''}

def uptime():
    p=read('/proc/uptime',128).split()
    return decimal(p[0]) if p else 0.0

def cpu_topology():
    result={}
    for name in os.listdir('/sys/devices/system/cpu') if os.path.isdir('/sys/devices/system/cpu') else []:
        if not re.fullmatch(r'cpu\d+',name): continue
        root=f'/sys/devices/system/cpu/{name}/topology'
        result[name]={'core_id':number(read(root+'/core_id').strip(),-1),'package_id':number(read(root+'/physical_package_id').strip(),-1),'siblings':read(root+'/thread_siblings_list',128).strip(),'online':read(f'/sys/devices/system/cpu/{name}/online',8).strip() or '1'}
    return result

def kernel_settings():
    paths={'sched_autogroup_enabled':'/proc/sys/kernel/sched_autogroup_enabled','sched_rr_timeslice_ms':'/proc/sys/kernel/sched_rr_timeslice_ms','sched_rt_runtime_us':'/proc/sys/kernel/sched_rt_runtime_us','sched_rt_period_us':'/proc/sys/kernel/sched_rt_period_us','sched_child_runs_first':'/proc/sys/kernel/sched_child_runs_first','sched_schedstats':'/proc/sys/kernel/sched_schedstats','sched_migration_cost_ns':'/proc/sys/kernel/sched_migration_cost_ns'}
    return {k:read(v,256).strip() or None for k,v in paths.items()}

def cgroup_for(pid,tid):
    return read(f'/proc/{pid}/task/{tid}/cgroup',8192).strip().splitlines()[:8]

def enumerate_threads(args):
    tasks={}
    errors=collections.Counter()
    ids=[int(p) for p in os.listdir('/proc') if p.isdigit()]
    ids.sort()
    for pid in ids:
        if args.pid and pid not in args.pid: continue
        root=f'/proc/{pid}/task'
        try: tids=[int(v) for v in os.listdir(root) if v.isdigit()]
        except OSError:
            errors['task_directory']+=1
            continue
        for tid in tids:
            if len(tasks)>=args.max_tasks:
                errors['task_limit']+=1
                return tasks,dict(errors)
            st=parse_stat(pid,tid)
            if st is None:
                errors['stat']+=1
                continue
            if args.name and not any(fnmatch.fnmatch(st['comm'],p) for p in args.name): continue
            status=status_fields(pid,tid)
            try: uid=number(status.get('Uid','').split()[0],-1)
            except IndexError: uid=-1
            if args.uid is not None and uid!=args.uid: continue
            counters=schedstat(pid,tid)
            item={'pid':pid,'tid':tid,'name':st['comm'],'state':st['state'],'ppid':st['ppid'],'uid':uid,'processor':st['processor'],'priority':st['priority'],'nice':st['nice'],'policy':st['policy'],'policy_name':POLICIES.get(st['policy'],str(st['policy'])),'starttime':st['starttime'],'utime_ticks':st['utime'],'stime_ticks':st['stime'],'delayacct_ticks':st['delayacct_ticks'],'voluntary_switches':number(status.get('voluntary_ctxt_switches',0)),'involuntary_switches':number(status.get('nonvoluntary_ctxt_switches',0)),'runtime_ns':counters['runtime_ns'],'wait_ns':counters['wait_ns'],'timeslices':counters['timeslices']}
            if args.extended:
                item['sched']=sched_extra(pid,tid)
                item['affinity']=affinity(pid,tid)
                item['cgroup']=cgroup_for(pid,tid)
            tasks[f'{pid}:{tid}:{st["starttime"]}']=item
    return tasks,dict(errors)

def collect(args):
    started=time.monotonic()
    tasks,errors=enumerate_threads(args)
    ts=time.time()
    return {'schema':1,'app':'sched-forensics','version':VERSION,'host':socket.gethostname(),'timestamp':ts,'timestamp_iso':utc(ts),'uptime_seconds':uptime(),'load':loadavg(),'psi':{name:read_psi(name) for name in ('cpu','memory','io')},'cpu':cpu_stat(),'schedstat':sched_system() if args.system_schedstat else {},'topology':cpu_topology() if args.topology else {},'kernel':kernel_settings() if args.kernel else {},'tasks':tasks,'errors':errors,'collection_seconds':time.monotonic()-started}

def counter_delta(a,b):
    if a is None or b is None: return None
    if not isinstance(a,(int,float)) or not isinstance(b,(int,float)): return None
    if b<a: return None
    return b-a

def cpu_usage(a,b):
    values={}
    for name,current in b.items():
        old=a.get(name)
        if not old: continue
        length=min(len(old),len(current))
        if length<4: continue
        prev=old[:length]
        curr=current[:length]
        total=sum(curr[:8])-sum(prev[:8]) if length>=8 else sum(curr)-sum(prev)
        idle=(curr[3]-prev[3])+(curr[4]-prev[4] if length>4 else 0)
        if total>0 and 0<=idle<=total:
            values[name]=round(max(0,min(100,100*(1-idle/total))),3)
    return values

def psi_delta(a,b,elapsed):
    result={}
    for resource,levels in b.items():
        result[resource]={}
        for level,values in levels.items():
            old=a.get(resource,{}).get(level,{})
            delta=counter_delta(old.get('total'),values.get('total'))
            result[resource][level]={'avg10':values.get('avg10'),'avg60':values.get('avg60'),'avg300':values.get('avg300'),'stall_pct_interval':round(min(100,ratio(delta,elapsed*1e6)),4) if delta is not None and elapsed>0 else None}
    return result

def task_delta(old,new,elapsed,ticks):
    item={k:new.get(k) for k in ('pid','tid','name','state','ppid','uid','processor','priority','nice','policy','policy_name','starttime')}
    keys=('runtime_ns','wait_ns','timeslices','utime_ticks','stime_ticks','delayacct_ticks','voluntary_switches','involuntary_switches')
    for key in keys: item['delta_'+key]=counter_delta(old.get(key),new.get(key))
    runtime=item['delta_runtime_ns']
    waiting=item['delta_wait_ns']
    switches=item['delta_voluntary_switches']
    involuntary=item['delta_involuntary_switches']
    item['cpu_pct_core']=round(100*runtime/(elapsed*1e9),3) if runtime is not None and elapsed>0 else None
    if item['cpu_pct_core'] is None:
        cpu_ticks=item['delta_utime_ticks']
        sys_ticks=item['delta_stime_ticks']
        if cpu_ticks is not None and sys_ticks is not None and elapsed>0:
            item['cpu_pct_core']=round(100*(cpu_ticks+sys_ticks)/(ticks*elapsed),3)
    item['wait_pct_interval']=round(100*waiting/(elapsed*1e9),3) if waiting is not None and elapsed>0 else None
    item['wait_runtime_ratio']=round(waiting/max(runtime,1),4) if waiting is not None and runtime is not None else None
    item['voluntary_switches_per_s']=round(switches/elapsed,3) if switches is not None and elapsed>0 else None
    item['involuntary_switches_per_s']=round(involuntary/elapsed,3) if involuntary is not None and elapsed>0 else None
    item['migrated']=old.get('processor')!=new.get('processor')
    item['cpu_changed_from']=old.get('processor') if item['migrated'] else None
    item['sched']=new.get('sched',{})
    item['affinity']=new.get('affinity')
    item['cgroup']=new.get('cgroup')
    if 'sched' in new and 'sched' in old:
        item['delta_nr_migrations']=counter_delta(old['sched'].get('nr_migrations'),new['sched'].get('nr_migrations'))
        item['delta_nr_switches']=counter_delta(old['sched'].get('nr_switches'),new['sched'].get('nr_switches'))
    return item

def compare(a,b,args):
    if a.get('schema')!=1 or b.get('schema')!=1: raise ValueError('unsupported snapshot schema')
    if a.get('host')!=b.get('host') and not args.allow_cross_host: raise ValueError('different hosts; use --allow-cross-host to compare')
    if b.get('uptime_seconds',0)<a.get('uptime_seconds',0) and not args.allow_reboot: raise ValueError('system reboot detected; use --allow-reboot to compare')
    elapsed=b.get('timestamp',0)-a.get('timestamp',0)
    if elapsed<=0: raise ValueError('snapshots must have increasing timestamps')
    ticks=os.sysconf('SC_CLK_TCK')
    old=a.get('tasks',{})
    new=b.get('tasks',{})
    common=old.keys() & new.keys()
    tasks=[task_delta(old[k],new[k],elapsed,ticks) for k in common]
    tasks.sort(key=lambda t:(-(t.get('cpu_pct_core') or 0),-(t.get('wait_pct_interval') or 0),t['pid'],t['tid']))
    result={'schema':1,'app':'sched-forensics','version':VERSION,'host':b.get('host'),'timestamp_iso':b.get('timestamp_iso'),'elapsed_seconds':round(elapsed,6),'task_count_before':len(old),'task_count_after':len(new),'task_count_common':len(common),'started':[new[k] for k in sorted(new.keys()-old.keys())][:args.max_events],'exited':[old[k] for k in sorted(old.keys()-new.keys())][:args.max_events],'cpu_usage':cpu_usage(a.get('cpu',{}),b.get('cpu',{})),'psi':psi_delta(a.get('psi',{}),b.get('psi',{}),elapsed),'load':b.get('load',{}),'tasks':tasks,'findings':[],'summary':{}}
    result['findings']=detect(result,args)
    result['summary']=summarize(result)
    return result

def finding(severity,kind,task,detail,metric=None,value=None):
    return {'severity':severity,'kind':kind,'pid':task.get('pid'),'tid':task.get('tid'),'name':task.get('name'),'detail':detail,'metric':metric,'value':value}

def detect(result,args):
    findings=[]
    for t in result['tasks']:
        cpu=t.get('cpu_pct_core')
        wait=t.get('wait_pct_interval')
        ratio_value=t.get('wait_runtime_ratio')
        invol=t.get('involuntary_switches_per_s')
        vol=t.get('voluntary_switches_per_s')
        if cpu is not None and cpu>=args.cpu_critical:
            findings.append(finding('critical','cpu-saturation',t,'thread consumes a high fraction of one logical CPU','cpu_pct_core',cpu))
        elif cpu is not None and cpu>=args.cpu_warning:
            findings.append(finding('warning','cpu-intensive',t,'sustained CPU consumption','cpu_pct_core',cpu))
        if wait is not None and wait>=args.wait_warning and (cpu or 0)>0.1:
            findings.append(finding('warning','runqueue-wait',t,'thread accumulated scheduler wait time','wait_pct_interval',wait))
        if ratio_value is not None and ratio_value>=args.wait_ratio and (t.get('delta_wait_ns') or 0)>args.min_wait_ns:
            findings.append(finding('warning','wait-runtime-imbalance',t,'scheduler wait time exceeds runtime','wait_runtime_ratio',ratio_value))
        if invol is not None and invol>=args.switch_warning:
            findings.append(finding('warning','involuntary-switch-storm',t,'high involuntary context-switch rate','involuntary_switches_per_s',invol))
        if vol is not None and vol>=args.switch_warning*2:
            findings.append(finding('info','voluntary-switch-storm',t,'high voluntary context-switch rate','voluntary_switches_per_s',vol))
        migrations=t.get('delta_nr_migrations')
        if migrations is not None and migrations>=args.migration_warning:
            findings.append(finding('warning','cpu-migration-churn',t,'scheduler migration counter increased substantially','delta_nr_migrations',migrations))
        elif t.get('migrated') and (cpu or 0)>=args.cpu_warning:
            findings.append(finding('info','cpu-placement-change',t,'CPU-intensive thread changed observed processor','processor',t['processor']))
        if t.get('policy') in (1,2,6) and (wait or 0)>=args.wait_warning:
            findings.append(finding('warning','realtime-wait',t,'real-time scheduling thread accumulated wait time','wait_pct_interval',wait))
    psi=result.get('psi',{}).get('cpu',{}).get('some',{})
    stall=psi.get('stall_pct_interval')
    if stall is not None and stall>=args.psi_warning:
        findings.append({'severity':'warning','kind':'system-cpu-pressure','pid':None,'tid':None,'name':'system','detail':'CPU pressure-stall time elevated','metric':'cpu_psi_stall_pct','value':stall})
    findings.sort(key=lambda x:({'critical':0,'warning':1,'info':2}[x['severity']],-(x['value'] if isinstance(x['value'],(int,float)) else 0)))
    return findings[:args.max_findings]

def summarize(result):
    tasks=result['tasks']
    cpu=[t['cpu_pct_core'] for t in tasks if t.get('cpu_pct_core') is not None]
    waits=[t['wait_pct_interval'] for t in tasks if t.get('wait_pct_interval') is not None]
    states=collections.Counter(t.get('state','?') for t in tasks)
    policies=collections.Counter(t.get('policy_name','?') for t in tasks)
    severities=collections.Counter(f['severity'] for f in result['findings'])
    return {'observed_threads':len(tasks),'cpu_pct_core_sum':round(sum(cpu),3),'cpu_pct_core_max':round(max(cpu,default=0),3),'wait_pct_interval_max':round(max(waits,default=0),3),'observed_cpu_migrations':sum(bool(t.get('migrated')) for t in tasks),'scheduler_migrations':sum(t.get('delta_nr_migrations') or 0 for t in tasks),'voluntary_switches':sum(t.get('delta_voluntary_switches') or 0 for t in tasks),'involuntary_switches':sum(t.get('delta_involuntary_switches') or 0 for t in tasks),'states':dict(states),'policies':dict(policies),'finding_severities':dict(severities)}

class Console:
    def __init__(self,args):
        self.args=args
        self.color=args.color=='always' or (args.color=='auto' and sys.stdout.isatty() and not os.environ.get('NO_COLOR'))
    def paint(self,value,color):
        return COLORS.get(color,'')+str(value)+COLORS['reset'] if self.color else str(value)
    def output(self,result):
        if self.args.json:
            print(json.dumps(result,indent=2 if self.args.pretty else None,allow_nan=False),flush=True)
            return
        print(self.paint('╔══════════════════════════════════════════════════════════════════════════════╗','purple'))
        print(self.paint('║ S C H E D  -  F O R E N S I C S     C O S M O S   /   v'+VERSION+'              ║','cyan'))
        print(self.paint('╚══════════════════════════════════════════════════════════════════════════════╝','purple'))
        print(self.paint(f"Host {result['host']}  {result['timestamp_iso']}  interval {result['elapsed_seconds']:.3f}s",'dim'))
        s=result['summary']
        print(self.paint(f"Threads {s['observed_threads']}  CPU sum {s['cpu_pct_core_sum']:.1f}%  migrations {s['scheduler_migrations']}  switches {s['voluntary_switches']}/{s['involuntary_switches']}",'blue'))
        print(self.paint('CPU usage by logical processor','violet'))
        cpus=sorted(result['cpu_usage'].items(),key=lambda x:(x[0]!='cpu',number(x[0][3:],-1)))
        for name,value in cpus[:self.args.top_cpus]:
            width=min(30,max(0,round(value*0.3)))
            tone='red' if value>=90 else 'yellow' if value>=70 else 'green'
            print(f' {name:<7} {self.paint("█"*width+"░"*(30-width),tone)} {value:6.2f}%')
        print(self.paint('Top threads by CPU','violet'))
        print(self.paint(f" {'PID':>7} {'TID':>7} {'CPU%':>8} {'WAIT%':>8} {'INV/s':>9} {'POLICY':<9} {'CPU':>4} NAME",'dim'))
        for t in result['tasks'][:self.args.top]:
            cpu=t.get('cpu_pct_core')
            wait=t.get('wait_pct_interval')
            inv=t.get('involuntary_switches_per_s')
            tone='red' if (cpu or 0)>=self.args.cpu_critical else 'yellow' if (cpu or 0)>=self.args.cpu_warning else 'white'
            line=f" {t['pid']:>7} {t['tid']:>7} {cpu if cpu is not None else 0:8.2f} {wait if wait is not None else 0:8.2f} {inv if inv is not None else 0:9.2f} {t['policy_name']:<9} {t['processor']:>4} {t['name'][:35]}"
            print(self.paint(line,tone))
        print(self.paint('Pressure stall information','violet'))
        for kind,levels in result.get('psi',{}).items():
            for level,values in levels.items():
                print(f" {kind:<7} {level:<5} avg10={values.get('avg10',0):6.2f}% interval={values.get('stall_pct_interval')}")
        if result['findings']:
            print(self.paint('Findings','violet'))
            for f in result['findings'][:self.args.top_findings]:
                tone={'critical':'red','warning':'yellow','info':'cyan'}[f['severity']]
                print(self.paint(f" {f['severity'].upper():8} {f['kind']:<28} {str(f['pid'] or '-'):>7}/{str(f['tid'] or '-'):>7} {f['detail']}",tone))
        else:
            print(self.paint('No findings at configured thresholds','green'))
        print(flush=True)

def write_csv(path,result):
    target=pathlib.Path(path)
    target.parent.mkdir(parents=True,exist_ok=True)
    fields=['timestamp_iso','host','elapsed_seconds','pid','tid','name','state','policy_name','processor','cpu_pct_core','wait_pct_interval','wait_runtime_ratio','voluntary_switches_per_s','involuntary_switches_per_s','delta_nr_migrations']
    fresh=not target.exists() or target.stat().st_size==0
    with target.open('a',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore')
        if fresh: writer.writeheader()
        for task in result['tasks']:
            row={**task,'timestamp_iso':result['timestamp_iso'],'host':result['host'],'elapsed_seconds':result['elapsed_seconds']}
            writer.writerow(row)

def nonnegative(value):
    v=float(value)
    if not math.isfinite(v) or v<0: raise argparse.ArgumentTypeError('must be finite and nonnegative')
    return v

def positive(value):
    v=nonnegative(value)
    if v<=0: raise argparse.ArgumentTypeError('must be positive')
    return v

def positive_int(value):
    v=int(value)
    if v<=0: raise argparse.ArgumentTypeError('must be positive')
    return v

def parser():
    p=argparse.ArgumentParser(prog='sched-forensics',description='Linux scheduler and process/thread forensic sampling, read-only')
    p.add_argument('--interval','-i',type=positive,default=1.0)
    p.add_argument('--count','-c',type=positive_int,default=1)
    p.add_argument('--continuous',action='store_true')
    p.add_argument('--pid',type=int,action='append')
    p.add_argument('--name',action='append',help='glob pattern for task comm, repeatable')
    p.add_argument('--uid',type=int)
    p.add_argument('--max-tasks',type=positive_int,default=100000)
    p.add_argument('--max-events',type=positive_int,default=100)
    p.add_argument('--max-findings',type=positive_int,default=200)
    p.add_argument('--extended',action='store_true',help='include sched, affinity and cgroup inspection')
    p.add_argument('--system-schedstat',action='store_true')
    p.add_argument('--topology',action='store_true')
    p.add_argument('--kernel',action='store_true')
    p.add_argument('--json',action='store_true')
    p.add_argument('--pretty',action='store_true')
    p.add_argument('--color',choices=('auto','always','never'),default='auto')
    p.add_argument('--theme',choices=('cosmos',),default='cosmos')
    p.add_argument('--top',type=positive_int,default=20)
    p.add_argument('--top-cpus',type=positive_int,default=24)
    p.add_argument('--top-findings',type=positive_int,default=20)
    p.add_argument('--csv')
    p.add_argument('--snapshot',help='write final raw snapshot to JSON')
    p.add_argument('--report',help='write final derived report to JSON')
    p.add_argument('--compare',nargs=2,metavar=('BEFORE','AFTER'),help='compare two saved raw snapshots')
    p.add_argument('--allow-cross-host',action='store_true')
    p.add_argument('--allow-reboot',action='store_true')
    p.add_argument('--cpu-warning',type=nonnegative,default=70)
    p.add_argument('--cpu-critical',type=nonnegative,default=95)
    p.add_argument('--wait-warning',type=nonnegative,default=30)
    p.add_argument('--wait-ratio',type=nonnegative,default=3)
    p.add_argument('--min-wait-ns',type=nonnegative,default=10000000)
    p.add_argument('--switch-warning',type=nonnegative,default=1000)
    p.add_argument('--migration-warning',type=nonnegative,default=20)
    p.add_argument('--psi-warning',type=nonnegative,default=20)
    p.add_argument('--version',action='version',version=VERSION)
    return p

def wait(seconds):
    deadline=time.monotonic()+seconds
    while RUNNING and time.monotonic()<deadline:
        time.sleep(min(.2,max(0,deadline-time.monotonic())))

def main(argv=None):
    args=parser().parse_args(argv)
    if args.cpu_critical<args.cpu_warning: raise ValueError('cpu-critical must be >= cpu-warning')
    signal.signal(signal.SIGINT,stop)
    signal.signal(signal.SIGTERM,stop)
    console=Console(args)
    if args.compare:
        result=compare(load_json(args.compare[0]),load_json(args.compare[1]),args)
        console.output(result)
        if args.report: write_json(args.report,result)
        if args.csv: write_csv(args.csv,result)
        return 0
    previous=collect(args)
    iteration=0
    while RUNNING:
        wait(args.interval)
        if not RUNNING: break
        current=collect(args)
        result=compare(previous,current,args)
        console.output(result)
        if args.csv: write_csv(args.csv,result)
        if args.report: write_json(args.report,result)
        if args.snapshot: write_json(args.snapshot,current)
        previous=current
        iteration+=1
        if not args.continuous and iteration>=args.count: break
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print(f'sched-forensics: {exc}',file=sys.stderr)
        raise SystemExit(1)
