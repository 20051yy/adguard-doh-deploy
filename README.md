# AdGuard Home + 加密 DNS 一键部署

在一台全新的 Ubuntu 22.04 / 24.04 VPS 上，一键部署 AdGuard Home，并按选择的模式提供明文或加密 DNS（DoH / DoT / DoQ）。交互式安装：运行后选模式、填参数即可，不用手动改配置文件。

## 四种模式

| 模式 | 包含什么 | 什么时候选 |
|------|---------|-----------|
| **1 明文** | AdGuard Home，DNS 走 UDP/TCP 53，管理面板自定义端口，无加密 | 局域网 / 可信网络，或只想先跑起来试试 |
| **2 加密直连 DoH** | AdGuard + acme.sh 证书（Cloudflare DNS 验证）+ nginx 反代 DoH，可选 sing-box VLESS+REALITY（443 端口，非 REALITY 握手回落到 nginx DoH） | 有 Cloudflare 托管域名，想直接用 443 提供加密 DNS |
| **3 加密经 Cloudflare Tunnel** | AdGuard + cloudflared 隧道，DoH 经隧道对外，不暴露服务器 IP，不需要源站证书、不需要 nginx | 直连 443 被运营商干扰，或不想暴露服务器 IP |
| **4 零依赖加密** | 只要一台 VPS：公网 IP 生成 sslip.io 域名，Let's Encrypt HTTP-01 签证书 + nginx 反代 DoH；直连不通（80/443 被拦）时自动切 trycloudflare 快速隧道兜底 | 没有域名、没有 Cloudflare 账号，只想一条命令装好加密 DNS |

四种模式的 AdGuard 过滤、广告拦截、查询日志都一样，区别只在“客户端到 AdGuard 这一段走不走加密、走哪条路”。

## 前置条件

- 一台 Ubuntu 22.04 / 24.04 VPS（root 权限）
- 模式 2 和 3：一个托管在 Cloudflare 的域名
- 模式 2：一个有对应域名 **DNS:Edit** 权限的 Cloudflare API Token
- 模式 3：部署过程中需要在浏览器里完成一次 Cloudflare 登录授权（`cloudflared tunnel login`）
- 模式 4：什么都不用——不需要域名、不需要 Cloudflare 账号、不需要 API Token、不需要浏览器登录，只要这台 VPS 有公网 IP（直连签证书要 80 端口能从外网访问；80/443 被拦也没关系，会自动切快速隧道兜底）

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/20051yy/adguard-doh-deploy/main/install.sh | sudo bash
```

> 也可以先下载再运行：`sudo bash install.sh`。

## 安装时会问什么

| 参数 | 说明 |
|------|------|
| 部署模式 | 1 明文 / 2 加密直连 DoH / 3 加密经 Cloudflare Tunnel / 4 零依赖加密 |
| AdGuard 管理员用户名 | 默认 `admin` |
| AdGuard 管理员密码 | 输入不回显，输两遍确认 |
| AdGuard 管理面板端口 | 默认 `32450`（不是 3000） |
| 上游 DNS | 默认 `https://dns10.quad9.net/dns-query,1.1.1.1` |
| DoH 域名（模式 2/3） | 例如 `doh.example.com`，只填域名，不要带 `https://` |
| Cloudflare API Token（模式 2） | 需要对应域名的 DNS:Edit 权限，输入不回显 |
| Cloudflare 账号邮箱（模式 2） | 用于 ZeroSSL 注册 |
| 证书颁发机构（模式 2） | 1）ZeroSSL（默认，ECC 证书） 2）Let's Encrypt |
| 是否安装 sing-box（模式 2） | 可选，VLESS+REALITY 占 443 端口 |
| REALITY 伪装域名 SNI（模式 2 选了 sing-box 时） | 默认 `www.microsoft.com` |
| 隧道名称（模式 3） | 默认 `adguard-doh`，不能含空格 |
| 是否跳过直连直接走快速隧道（模式 4） | 默认 `n`；选 `y` 或环境变量 `AGH_FORCE_TUNNEL=1` 直接走 trycloudflare 隧道，不试直连 |

所有参数也可以用环境变量预先传入（例如 `AGH_MODE=1 AGH_ADMIN_PASS=xxx sudo -E bash install.sh`），已设置的环境变量不会再提问。生成的 sing-box UUID、REALITY 密钥、隧道 ID、trycloudflare 隧道域名只写进本地凭据文件 `/root/adguard-doh-credentials`（权限 600），管理员密码和 Cloudflare API Token 不会写进这个文件。

## 验证是否成功

部署完成后脚本会自动验证。也可以手动验证：

```bash
# 一条真的 DoH 查询（查 example.com 的 A 记录），应返回 HTTP 200 application/dns-message
curl -s -i 'https://<你的DoH域名>/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' \
  -H 'accept: application/dns-message' | head -8
```

- 返回 `HTTP/2 200` + `Content-Type: application/dns-message` = 通了。
- 空查询（不带 `?dns=` 参数）返回 `HTTP 400 Bad Request` 是**正常的**，那是 AdGuard 对无参数请求的回应，不是故障。
- 再去 AdGuard 管理面板 → 查询日志：手机/电脑上网后应出现新记录，类型是 **DNS-over-HTTPS**，不再是“无加密 DNS”。

如果验证不通过，先看脚本最后的提示，再检查：域名是否解析到这台 VPS（模式 2）、隧道是否处于 Healthy（模式 3）、以及 `journalctl -u AdGuardHome -n 100`。

## 切换模式

重新运行一次安装脚本，选另一个模式即可。已有的 AdGuard 管理员账号会被保留（脚本检测到已有配置会原样保留 `users` 段，只更新端口和加密设置），原有配置会先备份一份再改。

注意一个 DNS 规矩：**同一个域名不能同时有 A 记录和 CNAME 记录**。模式 2 的 DoH 域名用 A 记录指到 VPS，模式 3 的 DoH 域名要用 CNAME 指到隧道（`tunnel route dns` 会自动创建）。如果想保留直连的域名、同时再开一个走隧道的，就用两个不同的子域名，例如 `doh.example.com` 直连、`doh2.example.com` 走隧道。

## 常见问题

- **管理面板打不开**：确认端口没被防火墙拦，地址是 `http://<VPS公网IP>:<你选的端口>/`（默认 32450）。
- **模式 2 证书签发失败**：先确认 Cloudflare API Token 有该域名的 DNS:Edit 权限，且域名确实托管在该 Cloudflare 账号下。
- **模式 2 的 DoH 连不上**：域名 A 记录必须指向这台 VPS 的公网 IP；等 DNS 生效后再测。
- **模式 3 需要浏览器**：`cloudflared tunnel login` 会打印一个网址，在你自己的电脑浏览器里打开完成授权，再回终端按回车继续。
- **模式 4 的 443 被拦怎么办**：不用管，脚本会自动处理。直连分两步验证：先签证书（要 80 端口能从外网访问），再验 443 的 DoH 查询；哪一步失败都会自动切到 trycloudflare 快速隧道兜底，最后打印出来的就是能用的 DoH 地址。如果两条路都失败，脚本会报错退出并说明原因，不会装完一个不能用的给你。
- **trycloudflare 域名变了怎么办**：快速隧道（`*.trycloudflare.com`）的域名每次重启 `adguard-quick-tunnel` 服务会重新分配，变了之后客户端要把 DoH 地址改成新域名（新域名在 `/root/adguard-doh-credentials` 里，`quick_tunnel_host` 这一行，服务重启后重新运行一次脚本会刷新它）。想要固定不变的域名，请用模式 3（需要 Cloudflare 账号）。
- **证书续期**：acme.sh 会自动续期，续期时自动重载 nginx 并重启 AdGuard；AdGuard 的证书直接引用 acme.sh 的文件路径，续期后无需手动改配置。
- **sing-box 凭据**：UUID、REALITY 公钥/私钥、short_id 都在 `/root/adguard-doh-credentials` 里，脚本最后也会打印一次。

## 文件说明

- `install.sh`：唯一的安装脚本，四个模式都在里面（可直接执行，也可 `source` 后单独调用里面的函数做测试）。
- `README.md`：本文件。
