"""
╔══════════════════════════════════════════════════════════════════════╗
║   ANTIGRAVITY DEEP PERSONALIZER — Módulo de Personalización Profunda ║
║   Scraping + Gemini Grounding → Hook de Apertura para correo frío    ║
╚══════════════════════════════════════════════════════════════════════╝

Instalación:
    pip install google-genai requests beautifulsoup4 pandas

Configuración:
    PowerShell : $env:GEMINI_API_KEY = "tu-llave"
    bash/zsh   : export GEMINI_API_KEY="tu-llave"

Uso:
    python antigravity_deep_personalizer.py

Flujo:
    CSV de entrada (columna URL/TIENDA)
        → Scraper con BeautifulSoup (about, blog, homepage)
        → Si scraping falla → Gemini con Google Search Grounding
        → Gemini genera PERSONALIZED_HOOK (≤25 words, English, US B2B market)
        → Leads_Con_Hook_Personalizado.csv
"""

import os
import sys
import time
import random
import logging
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup
from google import genai
from google.genai import types


# ─────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN CENTRAL
# ─────────────────────────────────────────────────────────────────────
ARCHIVO_ENTRADA  = "Base_Datos_Leads_Pilar2.csv"
ARCHIVO_SALIDA   = "Leads_Con_Hook_Personalizado.csv"
ARCHIVO_LOG      = "deep_personalizer.log"
SEPARADOR_CSV    = ";"
ENCODING_CSV     = "utf-8-sig"

MODELO_IA        = "gemini-2.5-flash"
MAX_REINTENTOS   = 3
BACKOFF_BASE     = 2
BACKOFF_MAX      = 60
SLEEP_ENTRE_LEADS = 10          # segundos entre leads para respetar rate limits
TIMEOUT_HTTP     = 12           # segundos de timeout por request HTTP
MAX_CHARS_SCRAPE = 4000         # máx caracteres de contexto enviados a Gemini

# Columnas que el script busca en el CSV para encontrar la URL de la tienda
# (en orden de prioridad)
COLUMNAS_URL     = ["URL", "TIENDA", "STORE_URL", "DOMINIO", "WEB"]

# Subrutas donde suele estar el contenido "about" en Shopify
ABOUT_PATHS = [
    "/pages/about",
    "/pages/about-us",
    "/pages/nuestra-historia",
    "/pages/our-story",
    "/pages/quienes-somos",
    "/pages/about-us/",
    "/about",
    "/about-us",
    "/nuestra-historia",
]

BLOG_PATHS = [
    "/blogs/news",
    "/blogs/novedades",
    "/blogs/noticias",
    "/blog",
]

# Pool de User-Agents reales (Chrome, Firefox, Safari — actualizados 2025)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]


# ─────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────
def _setup_logging() -> logging.Logger:
    log = logging.getLogger("personalizer")
    log.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(ch)

    fh = logging.FileHandler(ARCHIVO_LOG, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    ))
    log.addHandler(fh)

    return log

logger = _setup_logging()
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")


# ─────────────────────────────────────────────────────────────────────
# HELPERS — URL
# ─────────────────────────────────────────────────────────────────────
def normalizar_url(raw: str) -> str:
    """
    Asegura que la URL tenga esquema https:// y no tenga trailing slash.
    Ejemplos:
        "mitienda.com"      → "https://mitienda.com"
        "http://tienda.mx/" → "http://tienda.mx"
    """
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def _get_headers() -> dict:
    """Devuelve headers HTTP con un User-Agent aleatorio del pool."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-MX,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
    }


# ─────────────────────────────────────────────────────────────────────
# SCRAPING
# ─────────────────────────────────────────────────────────────────────
def _fetch_html(url: str) -> str | None:
    """
    Descarga el HTML de una URL. Retorna el texto o None si falla.
    Maneja timeouts, SSL, y redirecciones automáticamente.
    """
    try:
        resp = requests.get(
            url,
            headers=_get_headers(),
            timeout=TIMEOUT_HTTP,
            allow_redirects=True,
            verify=True,        # valida SSL; si falla, retorna None
        )
        if resp.status_code == 200:
            return resp.text
        logger.debug("  HTTP %d en %s", resp.status_code, url)
        return None
    except requests.exceptions.SSLError:
        # Segundo intento sin verificación SSL (algunas tiendas tienen certs expirados)
        try:
            resp = requests.get(
                url, headers=_get_headers(),
                timeout=TIMEOUT_HTTP, allow_redirects=True, verify=False,
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None
    except Exception as e:
        logger.debug("  Error HTTP en %s: %s", url, str(e)[:120])
        return None


def _extraer_texto_relevante(html: str) -> str:
    """
    Parsea el HTML con BeautifulSoup y extrae párrafos con contenido
    semántico (misión, valores, historia). Filtra navegación, footers,
    scripts y textos cortos de relleno.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Eliminar ruido: scripts, estilos, nav, footer, banners de cookies
    for tag in soup(["script", "style", "nav", "footer", "header",
                      "noscript", "iframe", "svg", "form",
                      "[class*='cookie']", "[class*='popup']"]):
        tag.decompose()

    parrafos = []
    for tag in soup.find_all(["p", "h1", "h2", "h3", "h4", "li", "blockquote"]):
        texto = tag.get_text(separator=" ", strip=True)
        # Filtrar párrafos demasiado cortos (menús, botones, etc.)
        if len(texto) >= 40:
            parrafos.append(texto)

    # Unir y recortar para no exceder el contexto de Gemini
    texto_completo = "\n\n".join(parrafos)
    return texto_completo[:MAX_CHARS_SCRAPE]


def scrape_tienda(base_url: str) -> tuple[str, str]:
    """
    Intenta extraer texto relevante de la tienda en este orden de prioridad:
      1. Páginas About (varias rutas)
      2. Últimos posts del blog
      3. Homepage como último recurso

    Retorna (texto_extraido, fuente) donde fuente describe de dónde vino el texto.
    Si no obtiene nada utilizable, retorna ("", "sin_scraping").
    """
    base = normalizar_url(base_url)
    if not base:
        return "", "url_invalida"

    # ── Prioridad 1: About pages ──────────────────────────────
    for path in ABOUT_PATHS:
        url = base + path
        html = _fetch_html(url)
        if html:
            texto = _extraer_texto_relevante(html)
            if len(texto) >= 100:   # mínimo para ser útil
                logger.debug("  Texto extraído desde: %s", url)
                return texto, url

    # ── Prioridad 2: Blog (últimos posts) ─────────────────────
    for path in BLOG_PATHS:
        url = base + path
        html = _fetch_html(url)
        if not html:
            continue
        soup = BeautifulSoup(html, "html.parser")
        # Buscar el primer artículo enlazado desde el índice del blog
        primer_link = None
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/blogs/" in href and href != path:
                primer_link = urljoin(base, href)
                break
        if primer_link:
            html_post = _fetch_html(primer_link)
            if html_post:
                texto = _extraer_texto_relevante(html_post)
                if len(texto) >= 100:
                    logger.debug("  Texto extraído desde blog: %s", primer_link)
                    return texto, primer_link

    # ── Prioridad 3: Homepage ─────────────────────────────────
    html = _fetch_html(base)
    if html:
        texto = _extraer_texto_relevante(html)
        if len(texto) >= 100:
            logger.debug("  Texto extraído desde homepage: %s", base)
            return texto, base

    return "", "sin_scraping"


# ─────────────────────────────────────────────────────────────────────
# PROMPT GEMINI — dos modos: con contexto scrapeado / con grounding puro
# ─────────────────────────────────────────────────────────────────────
def _construir_prompt_con_contexto(nombre_tienda: str, nicho: str,
                                    texto: str, fuente: str) -> str:
    return f"""
You are an Expert in Cold Email Copywriting with a focus on B2B sales psychology and corporate market analysis for the United States.

Your mission: process the scraped website information below and generate a 'Personalized Hook' (opening line) that instantly eliminates any suspicion of spam.

Store: "{nombre_tienda}" | Niche: "{nicho}"
Source: {fuente}

--- BEGIN SCRAPED CONTENT ---
{texto}
--- END SCRAPED CONTENT ---

GOLDEN RULES FOR THE HOOK:

1. Ultra-specificity: Mention a technical or operational detail that only someone who audited their brand would know (an award, HPLC certification, manufacturing philosophy, lifetime guarantee, peer-reviewed trials, proprietary process, etc.).

2. Zero Generic Flattery: FORBIDDEN phrases include 'I love your website', 'Great products', 'Hope you are doing well', or any variant. Be tactical, cold, and analytical.

3. Value Connection: Connect that specific detail with a competitive moat or a B2B acquisition gap that the brand has not yet exploited.

4. Elite example (for tone reference only — do NOT copy): 'Your peer-reviewed human trials per formula create an untapped B2B licensing moat that zero competitors can replicate at scale.'

5. Length: Maximum 25 words.

6. Language: STRICTLY ENGLISH (US Market).

OUTPUT:
Generate exclusively the opening line in English. No greetings, no signatures, no introductions, no quotation marks, no additional explanations. Just the raw hook.
""".strip()


def _construir_prompt_grounding(nombre_tienda: str, nicho: str, url: str) -> str:
    return f"""
You are an Expert in Cold Email Copywriting with a focus on B2B sales psychology and corporate market analysis for the United States.
You have access to real-time web search (Google Search Grounding). USE IT NOW.

Your mission: search for public information about the store "{nombre_tienda}" (URL: {url}), which sells products in the "{nicho}" niche, and generate a 'Personalized Hook' (opening line) that instantly eliminates any suspicion of spam.

SEARCH PRIORITIES:
Look for: awards, certifications (HPLC, GMP, USDA Organic, etc.), manufacturing philosophy, peer-reviewed studies, proprietary processes, founder story, lifetime guarantees, unique differentiators, recent product launches, or any operational detail that sets them apart.

GOLDEN RULES FOR THE HOOK:

1. Ultra-specificity: Mention a technical or operational detail that only someone who audited their brand would know (an award, HPLC certification, manufacturing philosophy, lifetime guarantee, peer-reviewed trials, proprietary process, etc.).

2. Zero Generic Flattery: FORBIDDEN phrases include 'I love your website', 'Great products', 'Hope you are doing well', or any variant. Be tactical, cold, and analytical.

3. Value Connection: Connect that specific detail with a competitive moat or a B2B acquisition gap that the brand has not yet exploited.

4. Elite example (for tone reference only — do NOT copy): 'Your peer-reviewed human trials per formula create an untapped B2B licensing moat that zero competitors can replicate at scale.'

5. Length: Maximum 25 words.

6. Language: STRICTLY ENGLISH (US Market).

OUTPUT:
Generate exclusively the opening line in English. No greetings, no signatures, no introductions, no quotation marks, no additional explanations. Just the raw hook.
""".strip()


# ─────────────────────────────────────────────────────────────────────
# LLAMADA A GEMINI — con y sin grounding
# ─────────────────────────────────────────────────────────────────────
def _llamar_gemini(client: genai.Client, prompt: str,
                   usar_grounding: bool = False) -> str | None:
    """
    Llama a Gemini con reintentos + backoff exponencial.
    usar_grounding=True activa Google Search para que el modelo
    pueda buscar información real cuando el scraping falló.
    """
    config = None
    if usar_grounding:
        config = types.GenerateContentConfig(
            tools=[types.Tool(google_search=types.GoogleSearch())]
        )

    for intento in range(1, MAX_REINTENTOS + 1):
        try:
            kwargs = dict(model=MODELO_IA, contents=prompt)
            if config:
                kwargs["config"] = config

            response = client.models.generate_content(**kwargs)

            if not response or not getattr(response, "text", None):
                raise ValueError("Respuesta vacía de la API.")

            # Limpiar el hook: sin comillas, sin saltos de línea
            hook = response.text.strip().strip('"').strip("'")
            hook = " ".join(hook.split())   # colapsar whitespace interno
            return hook

        except Exception as e:
            error_str = str(e)
            logger.debug("Gemini intento %d — error: %s", intento, error_str)

            if any(k in error_str for k in
                   ("429", "Exhausted", "Quota", "quota", "RESOURCE_EXHAUSTED")):
                logger.error(
                    "\n[PARADA TÁCTICA] Cuota diaria de Google agotada. "
                    "Progreso guardado. Intenta mañana."
                )
                sys.exit(0)

            espera = min(BACKOFF_BASE ** intento, BACKOFF_MAX)
            if intento < MAX_REINTENTOS:
                logger.warning(
                    "  [REINTENTO %d/%d] %s — esperando %ds...",
                    intento, MAX_REINTENTOS, error_str[:100], espera
                )
                time.sleep(espera)
            else:
                logger.error(
                    "  [FALLO FINAL] Gemini falló %d veces: %s",
                    MAX_REINTENTOS, error_str[:200]
                )

    return None


def generar_hook(client: genai.Client, nombre_tienda: str,
                 nicho: str, url: str) -> tuple[str, str]:
    """
    Orquesta el flujo completo para una tienda:
      1. Scraping → texto relevante
      2. Si hay texto → Gemini con contexto (sin grounding, más rápido)
      3. Si scraping falló → Gemini con Google Search Grounding

    Retorna (hook, método_usado).
    """
    logger.info("  Scrapeando: %s", url)
    texto_scrapeado, fuente = scrape_tienda(url)

    if texto_scrapeado:
        logger.info("  Contexto obtenido (%d chars). Generando hook con Gemini...",
                    len(texto_scrapeado))
        prompt = _construir_prompt_con_contexto(
            nombre_tienda, nicho, texto_scrapeado, fuente
        )
        hook = _llamar_gemini(client, prompt, usar_grounding=False)
        metodo = f"scraping:{fuente}"
    else:
        logger.info("  Scraping bloqueado/sin resultado. "
                    "Activando Gemini Search Grounding...")
        prompt = _construir_prompt_grounding(nombre_tienda, nicho, url)
        hook = _llamar_gemini(client, prompt, usar_grounding=True)
        metodo = "grounding_busqueda_web"

    if not hook:
        hook = "ERROR_HOOK"
        metodo = "fallo_total"

    return hook, metodo


# ─────────────────────────────────────────────────────────────────────
# UTILIDAD — detectar columna URL en el CSV
# ─────────────────────────────────────────────────────────────────────
def detectar_columna_url(columnas: list[str]) -> str | None:
    """
    Busca en las columnas del CSV cuál contiene las URLs de las tiendas,
    probando los nombres definidos en COLUMNAS_URL (case-insensitive).
    """
    columnas_lower = {c.lower(): c for c in columnas}
    for candidato in COLUMNAS_URL:
        if candidato.lower() in columnas_lower:
            return columnas_lower[candidato.lower()]
    return None


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main() -> None:

    logger.info(
        "\n╔══════════════════════════════════════════════════════════════════╗"
        "\n║   ANTIGRAVITY DEEP PERSONALIZER — Módulo de Personalización      ║"
        "\n╚══════════════════════════════════════════════════════════════════╝\n"
    )

    # ── 1. Validar API Key ────────────────────────────────────────────
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.critical(
            "[ERROR CRÍTICO] GEMINI_API_KEY no encontrada en el entorno.\n"
            "  PowerShell : $env:GEMINI_API_KEY = 'tu-llave'\n"
            "  bash/zsh   : export GEMINI_API_KEY='tu-llave'"
        )
        sys.exit(1)

    client = genai.Client(api_key=api_key)
    logger.debug("Cliente Gemini inicializado. Modelo: %s", MODELO_IA)

    # ── 2. Escanear carpeta y mostrar menú de CSVs disponibles ──────────
    carpeta_actual = Path(__file__).parent.resolve()
    archivos_csv   = sorted(carpeta_actual.glob("*.csv"))

    if not archivos_csv:
        logger.critical(
            "[ERROR] No se encontró ningún archivo .csv en la carpeta:\n"
            "  %s\n"
            "  Asegúrate de que tu archivo de leads está en el mismo\n"
            "  directorio que este script.",
            carpeta_actual
        )
        sys.exit(1)

    logger.info("CSVs disponibles en: %s\n", carpeta_actual)
    for i, archivo in enumerate(archivos_csv):
        # Mostrar tamaño aproximado como referencia visual
        kb = archivo.stat().st_size / 1024
        logger.info("  [%d] %-45s  %.1f KB", i, archivo.name, kb)

    logger.info("")

    # Pedir selección al usuario con validación de rango
    while True:
        try:
            raw = input(
                "┌─ SELECCIÓN DE ARCHIVO\n"
                f"└─▶ Ingresa el número del CSV a procesar [0-{len(archivos_csv)-1}]: "
            ).strip()
            eleccion = int(raw)
            if 0 <= eleccion < len(archivos_csv):
                break
            logger.warning(
                "  Número fuera de rango. Ingresa un valor entre 0 y %d.",
                len(archivos_csv) - 1
            )
        except ValueError:
            logger.warning("  Entrada inválida. Ingresa solo el número.")
        except (KeyboardInterrupt, EOFError):
            logger.info("\n[CANCELADO] Operación interrumpida por el usuario.")
            sys.exit(0)

    ARCHIVO_ENTRADA = str(archivos_csv[eleccion])
    logger.info("\n▶ Archivo seleccionado: %s\n", archivos_csv[eleccion].name)

    # Cargar el CSV elegido
    try:
        df = pd.read_csv(
            ARCHIVO_ENTRADA,
            sep=SEPARADOR_CSV,
            dtype=str,
            encoding=ENCODING_CSV,
            on_bad_lines='skip',
            engine='python',
        ).fillna("")
        logger.info("CSV cargado: %d filas — %s\n", len(df), archivos_csv[eleccion].name)
    except UnicodeDecodeError:
        # Fallback: algunos CSVs exportados en Windows usan latin-1
        try:
            df = pd.read_csv(
                ARCHIVO_ENTRADA, sep=SEPARADOR_CSV,
                dtype=str, encoding="latin-1",
                on_bad_lines='skip',
                engine='python',
            ).fillna("")
            logger.warning(
                "  Encoding UTF-8 falló. Archivo leído con latin-1. "
                "Considera guardarlo como UTF-8 para evitar problemas con tildes."
            )
            logger.info("CSV cargado: %d filas\n", len(df))
        except Exception as e:
            logger.critical("Error leyendo el CSV (latin-1 fallback): %s", e)
            sys.exit(1)
    except Exception as e:
        logger.critical("Error leyendo el CSV: %s", e)
        sys.exit(1)

    # ── 3. Detectar columna URL y columna NICHO ───────────────────────
    col_url = detectar_columna_url(list(df.columns))
    if not col_url:
        logger.critical(
            "[ERROR] No se encontró una columna de URL en el CSV.\n"
            "  Columnas detectadas: %s\n"
            "  Se esperaba una de: %s",
            list(df.columns), COLUMNAS_URL
        )
        sys.exit(1)
    logger.info("Columna URL detectada: '%s'", col_url)

    # Columna NICHO es opcional; si no existe se usa cadena vacía
    col_nicho = next(
        (c for c in df.columns if c.upper() in ("NICHO", "NICHE", "CATEGORIA")),
        None
    )
    if col_nicho:
        logger.info("Columna NICHO detectada: '%s'\n", col_nicho)
    else:
        logger.info("Columna NICHO no encontrada. Se usará valor vacío.\n")

    # ── 4. Garantizar columnas de salida ──────────────────────────────
    if "PERSONALIZED_HOOK" not in df.columns:
        df["PERSONALIZED_HOOK"] = ""
    if "HOOK_METHOD" not in df.columns:
        df["HOOK_METHOD"] = ""       # columna de auditoría: de dónde vino el hook

    # ── 5. Contar pendientes ──────────────────────────────────────────
    pendientes = df[
        (df[col_url].str.strip() != "") &
        (df["PERSONALIZED_HOOK"].str.strip().isin(["", "Pendiente", "ERROR_HOOK"]))
    ].index.tolist()

    total = len(pendientes)
    logger.info("Leads pendientes de personalizar: %d\n", total)

    if total == 0:
        logger.info("Todos los leads ya tienen hook. Nada que procesar.")
        sys.exit(0)

    # ── 6. Bucle principal ────────────────────────────────────────────
    stats = {"ok": 0, "error": 0, "omitidos": 0}

    for posicion, idx in enumerate(pendientes, start=1):
        row         = df.loc[idx]
        url_raw     = str(row[col_url]).strip()
        nicho       = str(row[col_nicho]).strip() if col_nicho else ""
        nombre      = str(row.get("TIENDA", url_raw)).strip() or url_raw

        # Limpiar nombre de tienda para usarlo en el prompt
        nombre_limpio = nombre.replace("https://", "").replace("http://", "")

        logger.info("─" * 60)
        logger.info("[%d/%d] %s", posicion, total, nombre_limpio)

        if not url_raw:
            logger.warning("  Sin URL. Omitiendo.")
            stats["omitidos"] += 1
            continue

        # Generar hook
        hook, metodo = generar_hook(client, nombre_limpio, nicho, url_raw)

        # Guardar en el DataFrame
        df.at[idx, "PERSONALIZED_HOOK"] = hook
        df.at[idx, "HOOK_METHOD"]       = metodo

        if hook and hook != "ERROR_HOOK":
            logger.info("  ✓ Hook: %s", hook)
            logger.info("  Método: %s", metodo)
            stats["ok"] += 1
        else:
            logger.warning("  ✗ No se pudo generar hook para %s", nombre_limpio)
            stats["error"] += 1

        # Guardado incremental: protege el progreso ante cualquier crash
        try:
            df.to_csv(ARCHIVO_SALIDA, sep=SEPARADOR_CSV,
                      index=False, encoding=ENCODING_CSV)
        except Exception as e:
            logger.error("  [ERROR GUARDADO] %s", e)

        # Pausa entre leads para no saturar rate limits de Gemini ni de las webs
        if posicion < total:
            time.sleep(SLEEP_ENTRE_LEADS)

    # ── 7. Resumen final ──────────────────────────────────────────────
    logger.info("\n" + "═" * 60)
    logger.info("  PERSONALIZACIÓN COMPLETADA — %s",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("═" * 60)
    logger.info("  Hooks generados exitosamente : %d", stats["ok"])
    logger.info("  Errores                      : %d", stats["error"])
    logger.info("  Omitidos (sin URL)            : %d", stats["omitidos"])
    logger.info("  Archivo de salida            : %s", ARCHIVO_SALIDA)
    logger.info("  Log completo                 : %s", ARCHIVO_LOG)
    logger.info("═" * 60 + "\n")


if __name__ == "__main__":
    main()
