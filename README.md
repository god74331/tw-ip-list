# tw-ip-list

台灣 IPv4 位址清單，資料來源為 APNIC 官方配發統計檔
`delegated-apnic-extended-latest`（含 MD5 校驗），篩選 `TW / ipv4 / allocated+assigned`，合併成 CIDR。

GitHub Actions 每天台灣時間 04:30 重新產生，網段有變動才 commit。

| 檔案 | 用途 |
|---|---|
| `tw-ip.rsc` | MikroTik 匯入檔，address-list 名稱 `TW` |
| `tw-ip.cidr` | 純網段清單，一行一個 |

MikroTik 取用：

```
/tool fetch url="https://raw.githubusercontent.com/god74331/tw-ip-list/main/tw-ip.rsc" dst-path=tw-ip.rsc
/import file-name=tw-ip.rsc
```

少於 500 段視為資料異常，不會輸出，也就不會覆蓋上一版。
