"""A deterministic target site with a hand-verified inventory of what is discoverable.

This module is the *reference answer*. Every claim SPYDER makes about this site
can be scored against ``TRUTH`` without appealing to another scanner, which is
what makes recall and false-positive numbers meaningful rather than relative.

Keep the site small enough that a human can verify the manifest by reading it.
"""
from __future__ import annotations

# --- pages -------------------------------------------------------------------
# path -> (status, extra headers, body)

_INDEX = """<!doctype html>
<html><head><title>Acme</title></head><body>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<a href="/products?id=1&amp;cat=tools">Products</a>
<a href="/admin">Admin</a>
<a href="/old-page">Old</a>
<a href="/legacy">Legacy</a>
<a href="https://external.example.com/off-scope">External</a>
<script src="/js/app.js"></script>
</body></html>"""

_ABOUT = """<!doctype html><html><body><h1>About</h1>
<a href="/team">Team</a></body></html>"""

_TEAM = "<!doctype html><html><body><h1>Team</h1></body></html>"

_CONTACT = """<!doctype html><html><body>
<form action="/contact-submit" method="post">
  <input name="name"><input name="email"><textarea name="message"></textarea>
</form></body></html>"""

_PRODUCTS = "<!doctype html><html><body><h1>Products</h1></body></html>"

# Endpoints reachable only by reading JS — the hard case for a crawler.
_APPJS = """
const API = "/api/v1/users";
fetch("/api/v1/orders").then(r => r.json());
const asset = "/static/img/logo.png";
"""

_SITEMAP_PAGE = "<!doctype html><html><body><h1>Sitemap only</h1></body></html>"

_ROBOTS = """User-agent: *
Disallow: /admin-panel
Disallow: /secret-area
Allow: /public
"""

_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://{host}/sitemap-only</loc></url>
  <url><loc>http://{host}/about</loc></url>
</urlset>"""

# A page with no technology indicators at all: fingerprinting it must yield
# "Unknown" rather than a guess.
_BLANK = "<!doctype html><html><body>nothing here</body></html>"

_HTML = {"Content-Type": "text/html; charset=utf-8"}

# --- fingerprint fixtures ----------------------------------------------------
# Pages under /fp/ exist to exercise one evidence source each. They are
# deliberately NOT linked from any crawlable page, so they do not perturb the
# crawler truth sets; the fingerprint harness fetches them by path.
#
# Half of them are *decoys*: pages that talk about a technology without
# exhibiting it. A correct engine reports Unknown for those, which is what
# makes a false-positive rate measurable.

_FP_DRUPAL = """<!doctype html><html><head>
<meta name="generator" content="Drupal 10 (https://www.drupal.org)">
</head><body><h1>Site</h1></body></html>"""

_FP_WORDPRESS = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.5.2">
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
</head><body><h1>Blog</h1></body></html>"""

_FP_REACT = """<!doctype html><html><body>
<div id="root" data-reactroot=""></div>
<script src="/static/js/main.8f2a1c.js"></script>
</body></html>"""

_FP_ANGULAR = """<!doctype html><html><body>
<app-root ng-version="17.1.0"></app-root>
</body></html>"""

_FP_NEXT = """<!doctype html><html><body><div id="__next"></div>
<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
</body></html>"""

_FP_JQUERY = """<!doctype html><html><head>
<script src="/js/jquery-3.7.1.min.js"></script>
</head><body>ok</body></html>"""

_FP_DJANGO = """<!doctype html><html><body>
<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="abc"></form>
</body></html>"""

# Decoy 1: names technologies in prose only. No structural marker anywhere.
_FP_DECOY_PROSE = """<!doctype html><html><head><title>Our stack</title></head><body>
<h1>Engineering blog</h1>
<p>Last year we migrated from WordPress to Drupal, and we are evaluating
whether nginx or Apache should terminate TLS. Our team also maintains a
jQuery plugin and an Express middleware.</p>
</body></html>"""

# Decoy 2: technology names embedded in unrelated paths/attributes. A
# substring matcher fires here; a structural matcher does not.
_FP_DECOY_PATHS = """<!doctype html><html><body>
<a href="/articles/wordpress-vs-drupal-2026">Comparison</a>
<img src="/img/react-conference-banner.png" alt="Angular and React meetup">
<script src="/js/not-jquery-really.js"></script>
</body></html>"""

# Decoy 3: a JSON API response that merely contains the words.
_FP_DECOY_JSON = '{"topic":"nginx tuning","tags":["php","express","laravel"]}'

_JS_CT = {"Content-Type": "application/javascript"}
_JSON_CT = {"Content-Type": "application/json"}

PAGES: dict[str, tuple[int, dict[str, str], str]] = {
    "/": (200, _HTML, _INDEX),
    "/about": (200, _HTML, _ABOUT),
    "/team": (200, _HTML, _TEAM),
    "/contact": (200, _HTML, _CONTACT),
    "/products": (200, _HTML, _PRODUCTS),
    "/js/app.js": (200, {"Content-Type": "application/javascript"}, _APPJS),
    "/sitemap-only": (200, _HTML, _SITEMAP_PAGE),
    "/public": (200, _HTML, _BLANK),
    "/admin": (403, _HTML, "<html><body>Forbidden</body></html>"),
    "/admin-panel": (200, _HTML, _BLANK),
    "/secret-area": (200, _HTML, _BLANK),
    "/blank": (200, {"Content-Type": "text/html"}, _BLANK),
    "/robots.txt": (200, {"Content-Type": "text/plain"}, _ROBOTS),
    "/new-page": (200, _HTML, "<html><body>New</body></html>"),
    # Redirect target one directory deep, holding a *relative* link. A crawler
    # that resolves links against the pre-redirect URL invents "/intro" here.
    "/docs/guide": (200, _HTML, '<html><body><a href="intro">Intro</a></body></html>'),
    "/docs/guide/intro": (200, _HTML, "<html><body>Intro</body></html>"),

    # --- fingerprint fixtures (unlinked; served WITHOUT the global stack
    # headers so each page carries exactly the evidence named in its truth row)
    "/fp/bare": (200, _HTML, _BLANK),
    "/fp/bare-json": (200, _JSON_CT, '{"ok":true}'),
    "/fp/nginx": (200, {**_HTML, "Server": "nginx/1.24.0"}, _BLANK),
    "/fp/apache": (200, {**_HTML, "Server": "Apache/2.4.58 (Ubuntu)"}, _BLANK),
    "/fp/php": (200, {**_HTML, "X-Powered-By": "PHP/8.2.15",
                      "Set-Cookie": "PHPSESSID=abc123; Path=/"}, _BLANK),
    "/fp/express": (200, {**_HTML, "X-Powered-By": "Express",
                          "Set-Cookie": "connect.sid=s%3Aabc; Path=/; HttpOnly"}, _BLANK),
    "/fp/aspnet": (200, {**_HTML, "X-AspNet-Version": "4.0.30319",
                         "Set-Cookie": "ASP.NET_SessionId=xyz; Path=/"}, _BLANK),
    "/fp/java": (200, {**_HTML, "Set-Cookie": "JSESSIONID=0A1B2C; Path=/"}, _BLANK),
    "/fp/laravel": (200, {**_HTML, "Set-Cookie": "laravel_session=eyJpdiI6; Path=/"}, _BLANK),
    # Two cookies folded into one header value — the wire-format edge case.
    "/fp/cloudflare": (200, {**_HTML, "cf-ray": "8a1b2c3d4e5f6789-LHR",
                             "cf-cache-status": "DYNAMIC",
                             "Set-Cookie": "__cf_bm=xyz; Path=/, cf_clearance=abc; Path=/"},
                       _BLANK),
    "/fp/drupal": (200, _HTML, _FP_DRUPAL),
    "/fp/wordpress": (200, _HTML, _FP_WORDPRESS),
    "/fp/react": (200, _HTML, _FP_REACT),
    "/fp/angular": (200, _HTML, _FP_ANGULAR),
    "/fp/nextjs": (200, _HTML, _FP_NEXT),
    "/fp/jquery": (200, _HTML, _FP_JQUERY),
    "/fp/django": (200, {**_HTML, "Set-Cookie": "csrftoken=t; Path=/"}, _FP_DJANGO),
    # Full stack: header + cookie + meta generator agree. The only page where
    # independent corroboration should push a technology to CONFIRMED.
    "/fp/stack": (200, {**_HTML, "Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.15",
                        "Set-Cookie": "PHPSESSID=abc123; Path=/"}, _FP_WORDPRESS),
    # Decoys: talk about technologies without exhibiting them.
    "/fp/decoy-prose": (200, _HTML, _FP_DECOY_PROSE),
    "/fp/decoy-paths": (200, _HTML, _FP_DECOY_PATHS),
    "/fp/decoy-json": (200, _JSON_CT, _FP_DECOY_JSON),
    "/fp/decoy-js": (200, _JS_CT, '// jquery and react are great; we use neither\n'),
}

#: Paths served WITHOUT :data:`GLOBAL_HEADERS`. Without this the site cannot
#: express "a response carrying no technology evidence", so Unknown and the
#: false-positive rate would be unmeasurable (every page would inherit the
#: global nginx/Express/cookie stack).
BARE_PATHS: frozenset[str] = frozenset(
    {p for p in PAGES if p.startswith("/fp/")} | {"/blank"}
)

REDIRECTS = {"/old-page": "/new-page", "/legacy": "/docs/guide/"}

# Headers served on every response. A coherent stack, so fingerprint evidence
# is checkable: nginx (Server), Express (X-Powered-By), an Express session cookie.
GLOBAL_HEADERS = {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express",
    "Set-Cookie": "connect.sid=s%3Aabc123; Path=/; HttpOnly",
}

# --- the reference answer ----------------------------------------------------

#: Paths a crawler starting at "/" should reach by following links only.
TRUTH_LINKED = {
    "/", "/about", "/team", "/contact", "/products", "/js/app.js",
    "/admin", "/old-page", "/new-page", "/contact-submit",
    "/legacy", "/docs/guide", "/docs/guide/intro",
}

#: Paths that must NEVER be reported. "/intro" is what a crawler invents when it
#: resolves the relative link on /docs/guide against the pre-redirect URL /legacy.
TRUTH_PHANTOM = {"/intro"}

#: Reachable only by parsing robots.txt.
TRUTH_ROBOTS_ONLY = {"/admin-panel", "/secret-area", "/public"}

#: Reachable only by parsing sitemap.xml.
TRUTH_SITEMAP_ONLY = {"/sitemap-only"}

#: Reachable only by extracting URLs from JavaScript.
TRUTH_JS_ONLY = {"/api/v1/users", "/api/v1/orders", "/static/img/logo.png"}

#: Must never appear: out of scope.
TRUTH_OUT_OF_SCOPE = {"https://external.example.com/off-scope"}

#: Forms, as (action, method, sorted field names).
TRUTH_FORMS = [("/contact-submit", "POST", ["email", "message", "name"])]

#: Query parameters that exist on the site.
TRUTH_PARAMS = {"/products": ["cat", "id"]}

#: Technologies with the evidence that proves each one.
TRUTH_TECH = {
    "nginx": ["Server: nginx/1.24.0"],
    "Express": ["X-Powered-By: Express", "connect.sid cookie"],
}

#: Paths that carry no technology signal — a correct engine reports Unknown.
#: Every one of these is in :data:`BARE_PATHS`, so the claim is actually true
#: of the bytes on the wire and not merely asserted here.
TRUTH_NO_TECH = {
    "/blank", "/fp/bare", "/fp/bare-json",
    "/fp/decoy-prose", "/fp/decoy-paths", "/fp/decoy-json", "/fp/decoy-js",
}

#: The fingerprint reference answer: path -> exactly the technologies a correct
#: engine reports there. An empty set means Unknown. Anything reported that is
#: not listed is a false positive; anything listed but not reported is a false
#: negative. Verify by reading the corresponding PAGES entry above.
TRUTH_FINGERPRINT: dict[str, set[str]] = {
    "/fp/bare": set(),
    "/fp/bare-json": set(),
    "/fp/decoy-prose": set(),
    "/fp/decoy-paths": set(),
    "/fp/decoy-json": set(),
    "/fp/decoy-js": set(),
    "/fp/nginx": {"Nginx"},
    "/fp/apache": {"Apache"},
    "/fp/php": {"PHP"},
    "/fp/express": {"Express"},
    "/fp/aspnet": {"ASP.NET"},
    "/fp/java": {"Java"},
    "/fp/laravel": {"Laravel"},
    "/fp/cloudflare": {"Cloudflare"},
    "/fp/drupal": {"Drupal"},
    "/fp/wordpress": {"WordPress"},
    "/fp/react": {"React"},
    "/fp/angular": {"Angular"},
    # Next.js only. Next.js is built on React, but this response contains no
    # React marker — crediting React here would be inference from a known
    # dependency, not evidence, and inference is how scanners start guessing.
    "/fp/nextjs": {"Next.js"},
    "/fp/jquery": {"jQuery"},
    "/fp/django": {"Django"},
    "/fp/stack": {"Nginx", "PHP", "WordPress"},
}

#: Versions the engine must extract, where the response states one.
TRUTH_VERSIONS: dict[str, dict[str, str]] = {
    "/fp/nginx": {"Nginx": "1.24.0"},
    "/fp/apache": {"Apache": "2.4.58"},
    "/fp/php": {"PHP": "8.2.15"},
    "/fp/drupal": {"Drupal": "10"},
    "/fp/wordpress": {"WordPress": "6.5.2"},
    "/fp/angular": {"Angular": "17.1.0"},
    "/fp/jquery": {"jQuery": "3.7.1"},
}

#: Where *independent* evidence sources corroborate one another, and a
#: technology may therefore be called CONFIRMED. Derived by reading the PAGES
#: entries above; each row names two evidence sources of different kinds:
#:
#:   /fp/php         X-Powered-By header  + PHPSESSID cookie
#:   /fp/express     X-Powered-By header  + connect.sid cookie
#:   /fp/aspnet      X-AspNet-Version hdr + ASP.NET_SessionId cookie
#:   /fp/cloudflare  cf-ray header        + __cf_bm cookie
#:   /fp/wordpress   meta generator       + /wp-content/ asset path
#:   /fp/stack       both of the above pairs (WordPress and PHP)
#:
#: Deliberately absent: /fp/nginx and /fp/apache (one header each — strong but
#: unverified, so HIGH), and /fp/django, where two *weak* sources agree (a CSRF
#: input and a cookie) but never reach the score a confirmation demands.
TRUTH_CORROBORATED: dict[str, set[str]] = {
    "/fp/php": {"PHP"},
    "/fp/express": {"Express"},
    "/fp/aspnet": {"ASP.NET"},
    "/fp/cloudflare": {"Cloudflare"},
    "/fp/wordpress": {"WordPress"},
    "/fp/stack": {"WordPress", "PHP"},
}


def all_truth_paths() -> set[str]:
    """Everything discoverable by a maximally capable crawler."""
    return TRUTH_LINKED | TRUTH_ROBOTS_ONLY | TRUTH_SITEMAP_ONLY | TRUTH_JS_ONLY
