本插件包含按 MIT 许可使用的上游代码，声明如下。

## 上游 fork

- `lib/providers/workbuddy/`
  来自 **dsh-workbuddy-connect**，Copyright (c) 2026 Corrine Hu（MIT License）。
  上游的凭据生命周期、目录缓存、回环 shim 原样保留；本仓库在其上做了本地补丁
  （多账号变体、倍率后缀、注册表接线）。

## 本项目自有代码

- `lib/providers/trae/`、`lib/providers/qoder/`
- `lib/index.js`、`lib/panel.js`、`lib/panel-client.js`、`lib/channel-registry.js`
- `lib/shared/`、`lib/client.js`（由 `panel-client.js` 等合成）

以上同样以 MIT License 发布，见 `LICENSE`。
