# MisGo：mis-go，不走米家寻常路

MisGo 是 [MiService](https://github.com/Yonsm/MiService) 的 Go 实现，提供小米账号、米家设备和小爱音箱的 Go 库，以及兼容 MiService 命令语法的 `misgo`。仅使用 Go 标准库。

## 安装

需要 Go 1.23 或更高版本：

```sh
go install github.com/Yonsm/misgo/cmd/misgo@latest
misgo
```

在源码目录构建：`go build -o misgo ./cmd/misgo`。

## 命令行

| 环境变量 | 用途 |
| --- | --- |
| `MI_USER` / `MI_PASS` | 小米账号和密码；有效的服务缓存可免输密码。服务要求短信或邮件 OTP 时在终端输入验证码。 |
| `MI_DID` | 设备 DID 或名称；云设备命令按名称子串匹配取首项，小爱音箱优先精确匹配 `miotDID`，再精确匹配名称。 |
| `MI_LOCAL` | `<IP>:<Token>`；非空时优先走 UDP，不访问云端，也不分发 `mina`、`spec` 或 `decode`。 |

CLI 使用 `~/.mi.token`，读取 MiService 的缓存格式，并以仅当前用户可读写的权限原子写入。未设置 `MI_USER` 时，有效缓存决定操作的是哪个账号。旧版缓存可能不含账号标识；切换账号前请移走旧缓存，自动化任务请使用独立的缓存。不要分享缓存，也不要把密码、设备 token 或 `list` 的输出提交到 Git。

`misgo` 不带参数显示完整帮助；`misgo --help`（也可用 `help`、`?`、`？`）显示当前云端或局域网模式的命令帮助。前置 `-v0` 到 `-v5` 分别表示关闭日志、严重、错误、警告、信息、调试；默认 `-v3`，单独 `-v` 等同 `-v4`。

### MiIO / MIoT 云端

先按需设置 `MI_USER`、`MI_PASS`。设备命令另需设置 `MI_DID`：

```sh
misgo list                       # name / model / did / token
misgo list 灯 true 0              # 名称子串、虚拟型号、华米设备开关
misgo list full                  # 原始设备记录
misgo home                       # 家庭、房间和设备 DID
misgo home full                  # 原始家庭记录
misgo home 我的家                 # 按家庭名称子串筛选

export MI_DID='客厅音箱'
misgo 2,2-2                      # 读属性；省略 -piid 时为 1
misgo 2=60,2-2=true               # 写属性
misgo 5 '你好'                    # 调动作；省略 -aiid 时为 1
misgo 5-4 '查询天气' 1
misgo 5-4 '[]'                    # 无参数动作使用 [] 占位
misgo power,brightness           # 传统 MiIO：读取命名属性
misgo power=on                   # 传统 MiIO：写入命名属性

misgo prop/get '[{"did":"123","siid":2,"piid":1}]'
misgo prop/set '[{"did":"123","siid":2,"piid":1,"value":60}]'
misgo action '{"did":"123","siid":5,"aiid":1,"in":["你好"]}'
misgo /home/device_list '{"getVirtualModel":false,"getHuamiDevices":0}'
```

属性值和动作参数会识别 `null`、布尔值和数字；用 `#` 或通过 shell 保留的单/双引号前缀强制字符串，例如 `misgo '2=#60'`。实际属性和动作取决于设备型号。像 Python 版一样，设备返回的业务码、`Invalid command` 和 `Device not found` 可能直接作为结果打印，不保证退出码非零；脚本应检查结果。

### 规格查询和离线解码

```sh
misgo spec                        # 型号到 URN 的索引
misgo spec speaker                # 按型号子串匹配
misgo spec xiaomi.wifispeaker.lx04         # 原始 JSON
misgo spec xiaomi.wifispeaker.lx04 text    # 可读命令表
misgo spec xiaomi.wifispeaker.lx04 python  # Python 枚举源码
misgo spec urn:miot-spec-v2:device:speaker:0000A015:xiaomi-lx04:1
misgo decode "$SSECURITY" "$NONCE" "$CIPHERTEXT" gzip
```

`spec` 访问公开的 `miot-spec.org`，不需要登录；`decode` 完全离线，`gzip` 可省略。命令行参数可能被本机进程列表看到；在共享主机上处理敏感密钥时建议调用 Go 库的 `Decode`。

### 小爱音箱（MiNA）

```sh
misgo mina                              # 列出小爱音箱
misgo mina '大家好'                      # 向所有音箱播报
export MI_DID='客厅音箱'
misgo mina pause
misgo mina stop
misgo mina play                         # 恢复播放
misgo mina play 'https://example.com/audio.mp3'  # URL 播放，设置列表循环
misgo mina loop 'https://example.com/audio.mp3'  # URL 播放，尝试设置单曲循环
misgo mina volume 50
misgo mina status
misgo mina ask                          # 最近的 AI 应答
```

`pause`、`stop`、`play`、`loop`、`volume`、`status`、`ask` 是保留子命令；如需播报包含这些字的一句话，可在前面加别的词。部分机型使用 `player_play_music`，其循环行为由固件和播放载荷决定。

### 局域网直连

```sh
export MI_LOCAL='192.168.1.10:0123456789abcdef0123456789abcdef'
misgo power,brightness
misgo power=on,brightness=80
misgo /miIO.info
misgo /set_power '["on"]'
unset MI_LOCAL
```

局域网默认使用 UDP 54321，需要设备实际的 16 字节十六进制 token 和可达的局域网地址。示例 token 只是占位符。

## 作为 Go 库使用

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/Yonsm/misgo"
)

func main() {
    ctx := context.Background()
    path, err := misgo.HomeTokenPath()
    if err != nil {
        log.Fatal(err)
    }
    account := misgo.NewMiAccount(os.Getenv("MI_USER"), os.Getenv("MI_PASS"),
        misgo.WithTokenPath(path))
    defer account.Close()

    miio := misgo.NewMiIOService(account, "cn")
    value, err := miio.MIoTGetProp(ctx, os.Getenv("MI_DID"), misgo.IID{SIID: 2, PIID: 1})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(value)
}
```

示例中的 `MI_DID` 应提供实际设备 ID。需要按名称查询、用 CLI 风格解析时，使用 `misgo.Command(ctx, miio, did, text)`。常用入口：

- `NewMiAccount`：默认在当前目录使用 `.mi.token`；可用 `WithTokenPath`、`WithTokenStore`、`WithOTPCallback`、`WithHTTPClient` 和 `WithLogger` 配置。`Login(ctx, sid)` 可预先建立会话；`MiRequestWith` 支持用重登后的会话重新签名。非交互服务应提供自己的 OTP 回调或传 `nil` 禁用交互。
- `NewMiIOService`：提供 `DeviceList`、`HomeList`、`MiIORequest`、`HomeRequest`、`MIoTRequest`、属性及动作方法。空区域和 `cn` 都走中国区，其他区域例如 `de`。
- `NewMiNAService`：提供 `DeviceList`、`TextToSpeech`、`SendMessage`、`Player*`、`PlayByURL`、`PlayByMusicURL` 与 `GetLatestAsk`。库方法使用 MiNA 的 `deviceID`。
- `NewMiIOLocalService`：提供 `Hello`、`Send`、`GetProp(s)`、`SetProp(s)`；可用 `LocalOptions` 调整 UDP 超时与重试次数。
- `Spec`、`NewSpecClient` 和 `Decode`：独立使用规格注册表、注入 HTTP 客户端或离线解码。

## 许可证

[MIT](LICENSE)。
