import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import flet as ft
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GEO_URL = "http://ip-api.com/json/?fields=status,countryCode,isp,hosting,query"
JUDGE_URL = "http://httpbin.org/get"
PROXY_HEADERS = {"via", "x-forwarded-for", "forwarded", "x-real-ip", "client-ip", "proxy-connection"}


def get_real_ip():
    try:
        return requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip", "")
    except Exception:
        return ""


def parse_proxy(line, default_proto="auto"):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    proto = None
    if "://" in line:
        proto, line = line.split("://", 1)
        proto = proto.lower()
    user = pw = host = port = None
    if "@" in line:
        auth, hp = line.rsplit("@", 1)
        if ":" in auth and ":" in hp:
            user, pw = auth.split(":", 1)
            host, port = hp.rsplit(":", 1)
    else:
        parts = line.split(":")
        if len(parts) == 2:
            host, port = parts
        elif len(parts) == 4:
            host, port, user, pw = parts
        else:
            return None
    if not host or not port or not port.isdigit():
        return None
    return {"raw": line, "proto": proto or default_proto, "host": host, "port": int(port), "user": user, "pw": pw}


def test_proto(p, proto, timeout, real_ip, target_url):
    scheme = "socks5h" if proto == "socks5" else ("socks4a" if proto == "socks4" else proto)
    auth = f"{p['user']}:{p['pw']}@" if p["user"] and p["pw"] else ""
    purl = f"{scheme}://{auth}{p['host']}:{p['port']}"

    s = requests.Session()
    s.proxies = {"http": purl, "https": purl}
    t0 = time.perf_counter()
    try:
        r = s.get(GEO_URL, timeout=timeout, verify=False)
        ping = round((time.perf_counter() - t0) * 1000)
        if r.status_code == 200 and r.json().get("status") == "success":
            d = r.json()
            exit_ip = d.get("query", "")
            anon = "Elite"
            try:
                jr = s.get(JUDGE_URL, timeout=timeout, verify=False).json()
                origin = str(jr.get("origin", ""))
                hdrs = {k.lower(): str(v) for k, v in jr.get("headers", {}).items()}
                if real_ip and (real_ip in origin or any(real_ip in v for v in hdrs.values())):
                    anon = "Transparent"
                elif "," in origin or any(h in hdrs for h in PROXY_HEADERS):
                    anon = "Anonymous"
            except Exception:
                anon = "Elite" if proto in ("socks4", "socks5") else "Anonymous"

            if target_url:
                tr = s.get(target_url, timeout=timeout, verify=False)
                if tr.status_code >= 400:
                    return {"live": False, "proxy": f"{p['host']}:{p['port']}", "info": f"Target HTTP {tr.status_code}"}

            return {
                "live": True,
                "formatted": f"{proto}://{auth}{p['host']}:{p['port']}",
                "proxy": f"{p['host']}:{p['port']}",
                "proto": proto.upper(),
                "anon": anon,
                "ping": ping,
                "country": d.get("countryCode", "??"),
                "isp": d.get("isp", ""),
            }
    except Exception:
        pass
    finally:
        s.close()
    return {"live": False, "proxy": f"{p['host']}:{p['port']}", "info": "Dead / Timeout"}


def check_one(line, proto, timeout, real_ip, target_url):
    p = parse_proxy(line, proto)
    if not p:
        return {"live": False, "proxy": line, "info": "Bad Format"}
    if p["proto"] == "auto":
        for cand in ["http", "socks5", "socks4"]:
            res = test_proto(p, cand, timeout, real_ip, target_url)
            if res["live"]:
                return res
        return {"live": False, "proxy": f"{p['host']}:{p['port']}", "info": "All Protocols Failed"}
    return test_proto(p, p["proto"], timeout, real_ip, target_url)


def main(page: ft.Page):
    page.title = "OmniProxy Checker v2.0"
    page.theme_mode = ft.ThemeMode.DARK
    page.scroll = ft.ScrollMode.ADAPTIVE
    page.padding = 16

    proxy_input = ft.TextField(
        label="Paste Proxies (One per line)",
        multiline=True,
        min_lines=5,
        max_lines=7,
        hint_text="192.168.1.1:8080\nsocks5://98.162.25.23:4145",
    )
    proto_dd = ft.Dropdown(
        label="Protocol",
        value="auto",
        options=[
            ft.dropdown.Option("auto", "Auto-Detect (HTTP/SOCKS5/4)"),
            ft.dropdown.Option("http", "HTTP / HTTPS"),
            ft.dropdown.Option("socks5", "SOCKS5"),
            ft.dropdown.Option("socks4", "SOCKS4"),
        ],
    )
    target_input = ft.TextField(label="Custom Target URL (Optional)", hint_text="https://www.google.com")
    status_txt = ft.Text("Ready", size=13, color=ft.colors.GREY_400)
    results_col = ft.Column(spacing=8)
    live_list = []

    def copy_live(e):
        if not live_list:
            page.snack_bar = ft.SnackBar(ft.Text("No live proxies to copy!"))
        else:
            page.set_clipboard("\n".join(live_list))
            page.snack_bar = ft.SnackBar(ft.Text(f"Copied {len(live_list)} live proxies!"))
        page.snack_bar.open = True
        page.update()

    def run_check(e):
        lines = [x.strip() for x in (proxy_input.value or "").splitlines() if x.strip()]
        if not lines:
            return
        live_list.clear()
        results_col.controls.clear()
        status_txt.value = f"Checking {len(lines)} proxies..."
        page.update()

        real_ip = get_real_ip()
        t_url = (target_input.value or "").strip()
        if t_url and not t_url.startswith(("http://", "https://")):
            t_url = "https://" + t_url

        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(check_one, ln, proto_dd.value, 7.0, real_ip, t_url) for ln in lines]
            for f in as_completed(futs):
                r = f.result()
                if r["live"]:
                    live_list.append(r["formatted"])
                    results_col.controls.append(
                        ft.Container(
                            padding=10,
                            border_radius=8,
                            bgcolor=ft.colors.GREEN_900,
                            content=ft.Text(
                                f"[LIVE] {r['proxy']} | {r['proto']} | {r['anon']} | {r['ping']}ms | {r['country']} ({r['isp']})",
                                size=12,
                            ),
                        )
                    )
                else:
                    results_col.controls.append(
                        ft.Container(
                            padding=10,
                            border_radius=8,
                            bgcolor=ft.colors.RED_900,
                            content=ft.Text(f"[DEAD] {r['proxy']} — {r['info']}", size=12),
                        )
                    )
                status_txt.value = f"Live: {len(live_list)} / Checked: {len(results_col.controls)} of {len(lines)}"
                page.update()

    page.add(
        ft.Text("OmniProxy Checker v2.0", size=22, weight=ft.FontWeight.BOLD),
        proxy_input,
        proto_dd,
        target_input,
        ft.Row(
            [
                ft.ElevatedButton("Start Check", on_click=run_check, expand=True),
                ft.OutlinedButton("Copy Live", on_click=copy_live),
            ]
        ),
        status_txt,
        ft.Divider(),
        results_col,
    )


ft.app(target=main)
