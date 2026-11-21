"""Banco Web: archivador acotado de sitios públicos y biblioteca de estudio."""
from __future__ import annotations
import ipaddress, json, os, re, socket, threading, uuid, zipfile, secrets
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urldefrag, unquote
from urllib.robotparser import RobotFileParser
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(os.getenv('BANCO_WEB_DATA', './data')).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
STATIC = Path(__file__).parent / 'static'
USER_AGENT = 'BancoWebResearchBot/0.2 (+authorized archival)'
MAX_BYTES, MAX_TOTAL, MAX_PAGES, MAX_ASSETS = 4_000_000, 40_000_000, 12, 90
app = FastAPI(title='Banco Web')
app.mount('/static', StaticFiles(directory=STATIC), name='static')
lock = threading.Lock()
jobs = {}
active = threading.BoundedSemaphore(2)
AUTH_USER = os.getenv("BANCO_WEB_USER", "")
AUTH_PASSWORD = os.getenv("BANCO_WEB_PASSWORD", "")
if bool(AUTH_USER) != bool(AUTH_PASSWORD):
    raise RuntimeError("Configura BANCO_WEB_USER y BANCO_WEB_PASSWORD conjuntamente")

@app.middleware("http")
async def require_auth(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if not AUTH_USER:
        return await call_next(request)
    from base64 import b64decode
    authorization = request.headers.get("authorization", "")
    verified = False
    if authorization.startswith("Basic "):
        try:
            u, p = b64decode(authorization[6:], validate=True).decode("utf-8").split(":", 1)
            verified = secrets.compare_digest(u, AUTH_USER) & secrets.compare_digest(p, AUTH_PASSWORD)
        except (ValueError, UnicodeDecodeError):
            verified = False
    if not verified:
        return JSONResponse({"detail":"Autenticación requerida"},status_code=401,headers={"WWW-Authenticate":"Basic realm=BancoWeb"})
    return await call_next(request)

@app.get("/health")
def health():
    return {"status": "ok"}

class Capture(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    max_pages: int = Field(default=4, ge=1, le=MAX_PAGES)
    note: str = Field(default='', max_length=3000)

class Notes(BaseModel):
    note: str = Field(max_length=3000)
    tags: str = Field(default='', max_length=250)

def validate_url(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ('https', 'http') or not p.hostname or p.username or p.password or p.port not in (None,80,443):
        raise ValueError('Solo URL http(s) públicas, sin credenciales')
    host = p.hostname.rstrip('.').lower()
    if host == 'localhost' or host.endswith(('.local', '.internal', '.localhost')):
        raise ValueError('Dominio privado no permitido')
    try:
        answers = socket.getaddrinfo(host, p.port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError('No se pudo resolver el dominio')
    for record in answers:
        ip = ipaddress.ip_address(record[4][0])
        if not ip.is_global:
            raise ValueError('Destino no público bloqueado')
    return url

def fetch(url: str) -> tuple[bytes, str, str]:
    # Validación por salto; antes de Internet requiere además firewall/proxy contra DNS rebinding.
    session = requests.Session()
    session.trust_env = False
    for _ in range(5):
        validate_url(url)
        with session.get(url, headers={'User-Agent': USER_AGENT}, timeout=(5, 15), stream=True, allow_redirects=False) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if not location: raise ValueError('Redirección sin destino')
                url = urljoin(url, location)
                continue
            response.raise_for_status()
            typ = response.headers.get('content-type', '').split(';')[0].strip().lower()
            if typ not in ('text/html','text/css','application/javascript','text/javascript','image/png','image/jpeg','image/webp','image/gif','image/svg+xml','font/woff','font/woff2','application/font-woff','application/octet-stream'):
                raise ValueError('Tipo de recurso no permitido')
            blob = bytearray()
            for chunk in response.iter_content(65536):
                blob.extend(chunk)
                if len(blob) > MAX_BYTES:
                    raise ValueError('Recurso demasiado grande')
            return bytes(blob), url, typ
    raise ValueError('Demasiadas redirecciones')

def safe_rel(url: str, html: bool) -> str:
    p = urlsplit(url)
    segments = []
    for part in p.path.split('/'):
        decoded = unquote(part)
        if not decoded or decoded == '.':
            continue
        if decoded == '..':
            decoded = '_parent_'
        sanitized = re.sub(r'[^\w.\-]', '_', decoded)[:80]
        if sanitized in ('', '.', '..'):
            sanitized = '_segment_'
        segments.append(sanitized)
    if not segments: segments = ['index.html']
    if p.path.endswith('/'): segments.append('index.html')
    elif html and not segments[-1].endswith(('.html','.htm')): segments.append('index.html')
    if p.query:
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, p.query).hex[:8]
        stem = segments[-1]
        if '.' in stem:
            a,b = stem.rsplit('.',1)
            segments[-1] = f'{a}_{suffix}.{b}'
        else:
            segments[-1] += '_' + suffix
    return '/'.join(segments)

def fetch_robots(url):
    validate_url(url)
    s = requests.Session(); s.trust_env = False
    with s.get(url,headers={'User-Agent': USER_AGENT}, timeout=(4,8), allow_redirects=False, stream=True) as r:
        if r.status_code == 404: return b'',url,'text/plain'
        r.raise_for_status()
        if r.is_redirect: raise ValueError('Redirección robots no soportada')
        blob=bytearray()
        for chunk in r.iter_content(65536):
            blob.extend(chunk)
            if len(blob)>500_000: raise ValueError('robots.txt demasiado grande')
        return bytes(blob),url,'text/plain'

def allowed_robots(root_url, target):
    p = urlsplit(root_url)
    robots = f'{p.scheme}://{p.netloc}/robots.txt'
    try:
        content, _, _ = fetch_robots(robots)
        parser = RobotFileParser()
        parser.parse(content.decode('utf-8',errors='replace').splitlines())
        return parser.can_fetch(USER_AGENT, target)
    except Exception:
        return False

def list_records():
    records = []
    for path in ROOT.glob('*/record.json'):
        try: records.append(json.loads(path.read_text(encoding='utf-8')))
        except Exception: pass
    return sorted(records,key=lambda x:x.get('created_at',''),reverse=True)

def capture_job(identifier, spec):
    folder = ROOT / identifier
    folder.mkdir(parents=True, exist_ok=True)
    site = folder / 'site'; site.mkdir()
    record = {'id':identifier, 'url': spec.url, 'note': spec.note, 'tags':'', 'created_at':datetime.now(timezone.utc).isoformat(), 'status':'running', 'files':0, 'pages':0, 'warnings':[]}
    visited = set(); asset_visited = {}; total = 0
    try:
        start = validate_url(spec.url)
        domain = urlsplit(start).netloc.lower()
        pending = deque([start]); title = ''
        while pending and record['pages'] < spec.max_pages:
            current = urldefrag(pending.popleft())[0]
            if current in visited or urlsplit(current).netloc.lower()!=domain: continue
            visited.add(current)
            if not allowed_robots(start,current):
                record['warnings'].append(f'robots.txt impide o no permite verificar: {current}')
                continue
            raw, final_url, content_type = fetch(current)
            if urlsplit(final_url).netloc.lower()!=domain:
                record['warnings'].append('Redirección fuera del dominio omitida')
                continue
            if content_type != 'text/html': continue
            total += len(raw)
            if total > MAX_TOTAL: raise ValueError('Límite total de descarga alcanzado')
            soup = BeautifulSoup(raw, 'html.parser')
            if not title: title = (soup.title.get_text(' ',strip=True) if soup.title else urlsplit(start).hostname)
            for tag, attr in [('a','href'),('img','src'),('script','src'),('link','href'),('source','src')]:
                for element in soup.find_all(tag):
                    value = element.get(attr)
                    if not value or value.startswith(('data:','blob:','mailto:','tel:','javascript:','#')): continue
                    absolute = urldefrag(urljoin(final_url,value))[0]
                    if urlsplit(absolute).netloc.lower() != domain: continue
                    if tag=='a':
                        if len(pending)+len(visited)<spec.max_pages*12: pending.append(absolute)
                        element[attr] = os.path.relpath(safe_rel(absolute,True),os.path.dirname(safe_rel(final_url,True)) or '.')
                        continue
                    if absolute in asset_visited:
                        relative = asset_visited[absolute]
                        element[attr]=os.path.relpath(relative, os.path.dirname(safe_rel(final_url,True)) or '.')
                        continue
                    if len(asset_visited)>=MAX_ASSETS: continue
                    if not allowed_robots(start, absolute): continue
                    try:
                        content, asset_url, asset_type = fetch(absolute)
                        if urlsplit(asset_url).netloc.lower()!=domain or asset_type=='text/html': continue
                        total += len(content)
                        if total>MAX_TOTAL: raise ValueError('Límite de bytes total')
                        relative = safe_rel(asset_url,False)
                        destination = site / relative
                        destination.parent.mkdir(parents=True,exist_ok=True)
                        destination.write_bytes(content)
                        asset_visited[absolute]=relative
                        record['files']+=1
                        element[attr]=os.path.relpath(relative, os.path.dirname(safe_rel(final_url,True)) or '.')
                    except Exception as exc:
                        record['warnings'].append(f'Recurso omitido: {absolute} ({str(exc)[:60]})')
            relative = safe_rel(final_url,True)
            dest = site / relative; dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_text(str(soup),encoding='utf-8')
            record['pages']+=1; record['files']+=1
            with lock: jobs[identifier]={'status':'running','pages':record['pages'],'files':record['files']}
        record['title']=title
        record['status']='complete' if record['pages'] else 'partial'
        if not record['pages']: record['warnings'].append('No se capturaron páginas: revisa robots.txt y permisos')
        with zipfile.ZipFile(folder/'archive.zip','w',zipfile.ZIP_DEFLATED) as z:
            for path in site.rglob('*'):
                if path.is_file(): z.write(path,path.relative_to(site))
            z.writestr('origen.json',json.dumps({'url':spec.url,'record_id':identifier},ensure_ascii=False))
    except Exception as exc:
        record['status']='error';record['warnings'].append(str(exc))
    finally:
        (folder/'record.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
        with lock: jobs[identifier]={'status':record['status'],'pages':record['pages'],'files':record['files']}

@app.get('/')
def home(): return FileResponse(STATIC/'index.html')

@app.get('/manifest.webmanifest')
def manifest(): return FileResponse(STATIC/'manifest.webmanifest',media_type='application/manifest+json')

@app.get('/api/library')
def library(): return list_records()

@app.post('/api/capture')
def new_capture(spec:Capture):
    try: validate_url(spec.url)
    except ValueError as exc: raise HTTPException(400,str(exc))
    identifier=uuid.uuid4().hex[:12]
    with lock: jobs[identifier]={'status':'queued','pages':0,'files':0}
    if not active.acquire(blocking=False):
        with lock: jobs.pop(identifier,None)
        raise HTTPException(429,'Máximo de capturas simultáneas alcanzado')
    def run():
        try: capture_job(identifier,spec)
        finally: active.release()
    threading.Thread(target=run,daemon=True).start()
    return {'id':identifier,'status':'queued'}

@app.get('/api/jobs/{identifier}')
def get_job(identifier:str):
    if not re.fullmatch('[0-9a-f]{12}',identifier): raise HTTPException(400)
    with lock: job=jobs.get(identifier)
    if job:return job
    f=ROOT/identifier/'record.json'
    return json.loads(f.read_text()) if f.exists() else {'status':'not_found'}

@app.patch('/api/library/{identifier}')
def update(identifier:str,notes:Notes):
    if not re.fullmatch('[0-9a-f]{12}',identifier): raise HTTPException(400)
    f=ROOT/identifier/'record.json'
    if not f.exists(): raise HTTPException(404)
    record=json.loads(f.read_text(encoding='utf-8'))
    record.update(note=notes.note,tags=notes.tags)
    f.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    return record

@app.get('/api/library/{identifier}/download')
def download(identifier:str):
    if not re.fullmatch('[0-9a-f]{12}',identifier): raise HTTPException(400)
    f=ROOT/identifier/'archive.zip'
    if not f.exists(): raise HTTPException(404)
    return FileResponse(f,filename=f'banco-web-{identifier}.zip',media_type='application/zip')
