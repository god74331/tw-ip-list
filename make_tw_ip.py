"""從 RIR 官方配發統計檔產生台灣 IP 清單（MikroTik .rsc 格式）。

用法：
    python make_tw_ip.py                 # 只用 APNIC
    python make_tw_ip.py --all-rirs      # 五大 RIR 全抓（含 ARIN/RIPE/LACNIC/AFRINIC 登記為 TW 的段）
    python make_tw_ip.py --country JP    # 其他國家

產出（與本檔同資料夾）：
    tw-ip.rsc   MikroTik 匯入檔，清單名 TW，格式與 iwik.org 相同，可直接給 tw-ip-update 腳本用
    tw-ip.cidr  純網段清單，一行一個
"""
import argparse
import hashlib
import ipaddress
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

RIRS = {
    "apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
MIN_ENTRIES = 500  # 少於這個數字視為資料異常，不輸出


def fetch(url, tries=3):
    """國外主機偶爾會下載到一半斷線，失敗就重試。"""
    for i in range(1, tries + 1):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return r.read()
        except Exception as e:
            if i == tries:
                raise
            print(f"  下載失敗（{e.__class__.__name__}），第 {i} 次重試")


def verify_md5(name, url, data):
    """APNIC/RIPE 等有提供 .md5 檔，下載後比對，確認檔案完整未被竄改或截斷。"""
    try:
        ref = fetch(url + ".md5").decode("ascii", "replace")
    except Exception:
        print(f"  {name}: 沒有 .md5 檔，略過校驗")
        return
    digest = hashlib.md5(data).hexdigest()
    if digest not in ref.lower():
        sys.exit(f"  {name}: MD5 不符，檔案可能損毀或被竄改，中止")
    print(f"  {name}: MD5 校驗通過")


def parse(data, country):
    """解析 delegated 檔，回傳該國 IPv4 網段。

    格式：registry|cc|type|start|value|date|status[|opaque-id]
    IPv4 的 value 是 IP 數量，不一定是 2 的次方，所以用 summarize_address_range 拆成 CIDR。
    """
    nets = []
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith("#"):
            continue
        f = line.split("|")
        if len(f) < 7 or f[1] != country or f[2] != "ipv4":
            continue
        if f[6] not in ("allocated", "assigned"):
            continue
        start = ipaddress.IPv4Address(f[3])
        end = start + int(f[4]) - 1
        nets.extend(ipaddress.summarize_address_range(start, end))
    return nets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--country", default="TW")
    ap.add_argument("--all-rirs", action="store_true")
    ap.add_argument("--list-name", default="TW")
    args = ap.parse_args()

    sources = RIRS if args.all_rirs else {"apnic": RIRS["apnic"]}
    nets = []
    for name, url in sources.items():
        print(f"下載 {name} ...")
        data = fetch(url)
        verify_md5(name, url, data)
        got = parse(data, args.country)
        print(f"  {name}: {len(got)} 段")
        nets.extend(got)

    nets = list(ipaddress.collapse_addresses(nets))  # 合併相鄰、去重
    if len(nets) < MIN_ENTRIES:
        sys.exit(f"只有 {len(nets)} 段，少於 {MIN_ENTRIES}，視為異常不輸出")

    out = Path(__file__).with_name(f"{args.country.lower()}-ip.rsc")
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f'/log info "Loading {args.country} ipv4 address list ({len(nets)} entries, built {stamp})"',
        f"/ip firewall address-list remove [/ip firewall address-list find list={args.list_name}]",
        "/ip firewall address-list",
    ]
    lines += [f":do {{ add address={n} list={args.list_name} }} on-error={{}}" for n in nets]
    out.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    out.with_suffix(".cidr").write_text("\n".join(map(str, nets)) + "\n", encoding="ascii", newline="\n")

    total = sum(n.num_addresses for n in nets)
    print(f"完成：{len(nets)} 段，共 {total:,} 個 IP → {out}")


if __name__ == "__main__":
    main()
