# 黑冰匣 BLACKICE

红黄蓝三色赛博朋克风格 · 本地加密保险库 · 纯原生三件套零依赖。

## 运行

**必须通过 HTTP 服务器访问**（`file://` 无法加载 ES 模块）：

```
# 任选其一
npx serve .
python -m http.server 8787
```

推荐部署到 GitHub Pages / Vercel 等静态托管。

## 文件清单（部署请完整上传 8 个文件）

| 文件 | 职责 |
|---|---|
| index.html | 结构 + 启动脚本 |
| style.css | 全部样式（设计令牌见 DESIGN-TOKENS.md） |
| app.js | 界面逻辑 / 渲染 / 交互 |
| vault.js | 数据模型 / 存储键 / 格式迁移 |
| crypto.js | AES-256-GCM + PBKDF2 加密 |
| sw.js | Service Worker（缓存版本 blackice-v4） |
| manifest.json / favicon.svg | PWA 与图标 |

## ⚠️ 数据安全三条铁律

1. **数据只存在浏览器 localStorage，按"访问地址 + 浏览器"隔离**——换地址或换浏览器 = 看到空库，不是数据丢了。主密码不可找回。
2. **定期「数据备份 → 导出加密备份」**：应用超 7 天未导出会在解锁后提醒。备份文件是密文，只能用备份时的主密码解密。
3. **首次打开若按钮显示「初始化并进入」= 该地址下没有旧数据**，此时创建的是全新空库（旧数据若存在会自动备份到 kv.vault.v2，但请不要依赖）。

## 存储结构（localStorage）

| 键 | 内容 |
|---|---|
| kv.salt | PBKDF2 盐 |
| kv.vault | 加密载荷 `{iv, ct}`（当前版本） |
| kv.vault.v2 | 迁移/覆盖前的旧密文自动备份 |
| kv.iter | PBKDF2 迭代次数 |
| kv.settings | 偏好设置 |
| kv.lastBackup | 上次导出备份时间 |

旧版（providers 格式）数据在解锁时自动迁移为新版 entries 格式，并附带密钥数/条目数完整性校验。

## 快捷键

- `Ctrl/⌘ + K`：命令面板（搜索 + 命令）
- `L`：锁定保险库（非输入状态）
- `Tab`：弹窗内焦点循环

## 设计体系

三色角色制（黄=权威 / 蓝=信息 / 红=能量）+ 黑底铁律 + 白色禁令
