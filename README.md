# codexRC

**Automated Web Security Auditing Tool** con backend único y dashboard web local.

> Solo usar en objetivos que tengas autorización para auditar.

## Arquitectura

- **Backend:** `backend/app.py` es la única implementación del servidor Flask.
- **Core:** autenticación, reconocimiento, detección tecnológica, CVE matcher y pipeline se ejecutan dentro del backend.
- **Frontend:** `frontend/index.html` solo presenta la interfaz y llama a la API `/api/*`.
- **Termux:** únicamente inicia el backend y mantiene disponible `localhost`; no contiene lógica de auditoría.
- `backend/main.py` existe solo como compatibilidad y reexporta la aplicación Flask; no es un segundo backend.

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
- `POST /api/scan` — ejecuta el pipeline completo en el backend.
- `GET /api/jobs` — lista los escaneos realizados en la sesión.
- `GET /api/jobs/<id>` — consulta un escaneo.
- `GET /api/pipeline/schema` — devuelve la estructura visual del pipeline.

Las credenciales y tokens se usan únicamente en memoria durante el escaneo y no se devuelven en la respuesta de autenticación.

## Funcionalidades

- Autenticación por cookies, login automático, Bearer token y header personalizado.
- Reconocimiento de headers, redirecciones, cookies y headers de seguridad.
- Detección tecnológica.
- Correlación de CVEs mediante CIRCL.
- Dashboard visual del pipeline.
