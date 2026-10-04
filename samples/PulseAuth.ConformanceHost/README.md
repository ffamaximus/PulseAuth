# PulseAuth.ConformanceHost

Servidor de autorización mínimo para ejecutar la **suite de conformidad de la OpenID Foundation**
(plan *Basic OP*: `oidcc-basic-certification-test-plan`) contra PulseAuth.

> No es una plantilla de producción: usa un usuario de prueba fijo, auto-login y una clave de firma
> de desarrollo (`pulseauth-tempkey.pem`, ignorada por git).

Ejecutar la suite es **gratis**. Solo la *certificación* (publicar los resultados con el logo
"OpenID Certified") es de pago.

---

## Qué expone

| | |
|---|---|
| Clientes | `conformance-client-1` y `conformance-client-2` (confidenciales, `client_secret_basic` / `client_secret_post`) |
| Scopes | `openid profile email phone offline_access` (scopes desconocidos como `address` se ignoran) |
| Usuario | `conformance-user`, con todos los claims estándar (nombre, email verificado, teléfono…) |
| Login | `/Account/Login` — con `AutoLogin=true` inicia sesión sin pedir nada (cada visita crea una sesión nueva, así `prompt=login` y `max_age` funcionan) |
| Logout | `/Account/Logout` — borra la sesión (necesario antes de `oidcc-prompt-none-not-logged-in`) |
| Info | `/` — muestra issuer, discovery y redirect URI configurados |

La configuración está en `appsettings.json` (sección `Conformance`) y se puede sobreescribir por
línea de comandos (`--Conformance:Issuer=...`).

---

## Opción A (recomendada): suite alojada + túnel HTTPS

La suite alojada en <https://www.certification.openid.net> es gratuita y no requiere instalar Java
ni Docker. Solo necesita llegar a tu servidor por HTTPS público, así que se usa un túnel.

### 1. Abrir el túnel

Con [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
(Windows: `winget install --id Cloudflare.cloudflared`):

```powershell
cloudflared tunnel --url http://localhost:5080
```

Copia la URL que imprime, por ejemplo `https://random-words.trycloudflare.com`.
(Con ngrok es equivalente: `ngrok http 5080`.)

> La URL de un *quick tunnel* cambia cada vez que reinicias cloudflared: si cambia, repite el paso 2
> y actualiza el JSON del paso 3.

### 2. Arrancar el host con ese issuer

Desde la raíz del repositorio:

```powershell
dotnet run --project samples/PulseAuth.ConformanceHost -- --Conformance:Issuer=https://random-words.trycloudflare.com
```

Comprueba en el navegador:

- `https://random-words.trycloudflare.com/` → página de info
- `https://random-words.trycloudflare.com/.well-known/openid-configuration` → el `issuer` debe ser
  exactamente la URL del túnel (sin `/` final)

### 3. Crear el plan de pruebas

1. Entra en <https://www.certification.openid.net> (login con Google o GitLab).
2. **Create a new test plan** → *OpenID Connect Core: Basic Certification Profile Authorization server test*.
3. Variantes: **Server metadata location** = `discovery`, **Client registration type** = `static_client`.
4. Pega la configuración de [`conformance-config.json`](conformance-config.json) reemplazando
   `CHANGE-ME` por el host del túnel:

```json
{
  "alias": "pulseauth-andres",
  "description": "PulseAuth - Basic OP",
  "server": { "discoveryUrl": "https://random-words.trycloudflare.com/.well-known/openid-configuration" },
  "client":  { "client_id": "conformance-client-1", "client_secret": "pulseauth-conformance-secret-1" },
  "client2": { "client_id": "conformance-client-2", "client_secret": "pulseauth-conformance-secret-2" },
  "consent": {}
}
```

El `alias` forma parte de la redirect URI registrada en los clientes
(`https://www.certification.openid.net/test/a/pulseauth-andres/callback`). Si lo cambias, cámbialo
también en `appsettings.json` (`Conformance:Alias`) o pásalo con `--Conformance:Alias=...`.

### 4. Ejecutar

Ejecuta los módulos uno a uno (o *Run all*). Cuando la suite muestre *"Waiting for browser"*, abre el
enlace: con auto-login la redirección vuelve sola a la suite.

---

## Opción B: suite local con Docker

Si prefieres no usar la suite alojada, se puede levantar en local siguiendo el README de
<https://gitlab.com/openid/conformance-suite> (build con Maven/Docker y `docker-compose up`; la UI queda
en `https://localhost.emobix.co.uk:8443`).

En ese caso:

- Usa igualmente el túnel del paso 1 (así el contenedor y el navegador llegan al servidor con un
  certificado válido).
- Arranca el host con la URL base de la suite local:
  `--Conformance:SuiteBaseUrl=https://localhost.emobix.co.uk:8443`

---

## Consejos y resultados esperados

| Módulo | Qué hacer / qué esperar |
|---|---|
| `oidcc-prompt-none-not-logged-in` | Visita antes `/Account/Logout` (o usa una ventana de incógnito). Esperado: `login_required`. |
| `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-redirect-uri-in-authorization-request` | PulseAuth muestra un error **sin redirigir** (correcto). La suite pide **subir una captura** de esa página: estado *REVIEW*. |
| `oidcc-codereuse-30seconds` | El código reutilizado se rechaza y los refresh tokens emitidos con él se revocan. El *access token* JWT ya emitido sigue siendo válido hasta que expira: probable **WARNING** (no es fallo). |
| `oidcc-claims-essential` | El parámetro `claims` no está soportado (`claims_parameter_supported=false`): se ignora, posible **WARNING**. |
| `oidcc-unsigned-request-object-…`, `oidcc-request-uri-…` | Se rechazan con `request_not_supported` / `request_uri_not_supported`: aceptado por la suite. |
| `oidcc-scope-address` | `address` no se publica en `scopes_supported`: la prueba se omite (*SKIPPED*). |
| `oidcc-display-*`, `oidcc-ui-locales`, `oidcc-login-hint`… | Parámetros opcionales que se ignoran: deberían pasar (algunos piden captura). |

Estados de la suite: **PASSED** / **WARNING** (aceptable, conviene revisar) / **REVIEW** (requiere
subir captura) / **FAILED** (hay que corregir) / **SKIPPED**.

### Reportar resultados

Al terminar, en la página del plan usa **Download all logs** (o copia el resumen de cada módulo con
*FAILED* / *WARNING*) y compártelo para revisar y corregir.

---

## Verificación previa

Antes de tu primera ejecución, el comportamiento que comprueba el plan *Basic OP* ya está cubierto
por `tests/PulseAuth.Tests/OidcConformanceTests.cs` y se validó contra este host simulando los
módulos principales (flujo de código, `prompt`, `max_age`, reutilización de código, refresh, UserInfo
GET/POST, errores de `redirect_uri`, request objects, discovery).
