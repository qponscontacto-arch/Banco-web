# Banco Web

Aplicación experimental para archivar y estudiar sitios web **públicos o autorizados** desde el teléfono, con backend Python y una interfaz adaptable a Android.

## Estado
- Captura limitada de HTML y recursos del mismo dominio; conserva rutas locales en el archivo ZIP.
- Biblioteca con títulos, etiquetas y notas.
- Máximo 12 páginas, 90 recursos, 4 MB por recurso y 40 MB por captura.
- No copia servidores privados, bases de datos, contraseñas, pagos ni garantiza espejos visuales perfectos.
- **No es un APK Android**: es una web móvil servida por FastAPI.
- No exponer directamente a Internet sin autenticación HTTPS, aislamiento y proxy de egreso.

## Inicio local

```bash
python -m venv .venv
source .venv/bin/activate # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Acceder a http://127.0.0.1:8000. Configurar `BANCO_WEB_USER` y `BANCO_WEB_PASSWORD` conjuntamente si se requiere Basic Auth. Nunca publicar sin HTTPS.

## Plan
1. Capture HTML pública con validación de URLs y robots.txt.
2. Pruebas automatizadas y almacenamiento persistente de biblioteca.
3. Playwright, capturas visuales, análisis de diseño, comparación y motor de tareas duradero.
4. Seguridad de egreso y despliegue privado HTTPS.
5. Empaquetado Android ligero y pruebas en teléfono.

Código propio independiente; no incorpora código de SiteOne Crawler. Usar únicamente sitios cuya captura esté autorizada.
