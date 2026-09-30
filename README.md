# codexRC

**Automated Web Security Auditing Tool** con backend único y dashboard web local.

> Solo usar en objetivos que tengas autorización para auditar.

## Arquitectura

- **Backend:** `backend/app.py` es la única implementación del servidor Flask.
- **Core:** autenticación, reconocimiento, detección tecnológica, CVE matcher y pipeline se ejecutan dentro del backend.
- **Frontend:** `frontend/index.html` solo presenta la interfaz y llama a la API `/api/*`.
- **Termux:** únicamente inicia el backend y mantiene disponible `localhost`; no contiene lógica de auditoría.
- `backend/main.py` existe solo como compatibilidad y reexporta la aplicación Flask; no es un segundo backend.
- **Logs:** cada escaneo se guarda en `reports/codexrc_<id>.json` y puede descargarse desde el dashboard; los eventos generales quedan en `reports/backend.log` en formato JSONL, con rotación automática y `request_id`.
- **Versión:** se muestra en la esquina del dashboard y en `GET /api/info`.
- **Verificación de sesión:** después de autenticar, el backend consulta una URL protegida, detecta redirecciones al login y busca el nombre visible del usuario.
- **Diagnóstico:** cada respuesta incluye `connection` y `diagnostics` para saber si el backend respondió, el objetivo fue alcanzable, la sesión fue verificada, qué usuario se detectó y qué solicitud revisar en los logs.

## Inicio en Termux

```bash
pkg update -y
pkg install python git -y
pip install --upgrade pip
pip install -r requirements.txt

git clone https://github.com/Eliezer1817/codexRC.git
cd codexRC
chmod +x start_termux.sh
./start_termux.sh
```

Luego abre en el navegador del teléfono:

**http://127.0.0.1:8000**

También puedes iniciar directamente con:

```bash
python backend/app.py
```

## API principal

- `GET /health` — estado del backend.
- `GET /api/info` — nombre y versión actual.
- `GET /api/status` — estado operativo, hora de inicio y jobs en memoria.
- `POST /api/scan` — ejecuta el pipeline completo en el backend.
- `GET /api/jobs` — lista los escaneos realizados en la sesión.
- `GET /api/jobs/<id>` — consulta un escaneo.
- `GET /api/jobs/<id>/log` — descarga el archivo JSON completo del escaneo.
- `GET /api/pipeline/schema` — devuelve la estructura visual del pipeline.

Las credenciales y tokens se usan únicamente en memoria durante el escaneo y no se devuelven en la respuesta de autenticación.

## Funcionalidades

- Autenticación por cookies, login automático, Bearer token y header personalizado.
- Reconocimiento de headers, redirecciones, cookies y headers de seguridad.
- Detección tecnológica.
- Correlación de CVEs mediante CIRCL.
- Dashboard visual del pipeline.

Para una comprobación confiable, completa **URL protegida para verificar sesión** con una ruta que requiera autenticación, por ejemplo `/account` o `/dashboard`. El resultado queda en `connection` y en `results.auth_status.data.session_check` con `authenticated`, `username`, `final_url`, `status_code`, `response_time`, `signals` y `reason`. Si se deja vacío, se usa la URL objetivo, pero una página pública no permite confirmar por completo que la sesión sea válida.
