# 更新日志

## 0.1.1

- 新增 `misgo version`，发布构建通过 `-ldflags` 注入版本。
- 增加 GitHub Actions 多平台构建与测试，以及 tag 触发的 goreleaser 发布。
- README 库示例改用当前分包 API，并加入可编译示例。

## 0.1.0

- 提供 `misgo` 命令行和 `account`、`miio`、`local`、`mina`、`spec` 等 Go 库包。
- 支持小米账号登录、短信和邮件 OTP、MiService 格式的服务令牌缓存与重新认证。
- 支持米家设备和家庭查询、MIoT 属性与动作、原始 MiIO 请求、公开规格查询、文本和 Python 格式，以及离线解码。
- 支持 MiIO 局域网 UDP 直连和小爱音箱的 TTS、播放、音量、状态及 AI 应答查询。
