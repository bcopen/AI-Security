# AI Security Scanner

AI驱动的自动化安全扫描工具，支持Web应用漏洞检测、渗透测试和安全评估。

## 功能特性

### 🔍 漏洞检测

| 漏洞类型 | 说明 |
|---------|------|
| SQL注入 | 基于错误回显 + 盲注检测 |
| XSS跨站脚本 | 反射型 + DOM型检测 |
| 命令注入 | 系统命令执行检测 |
| SSRF | 服务端请求伪造检测 |
| CSRF | 跨站请求伪造检测 |
| IDOR | 不安全直接对象引用 |
| 路径遍历 | 敏感文件读取检测 |
| 开放重定向 | 未验证重定向检测 |
| 敏感信息泄露 | API密钥、密码、Token检测 |
| SSL/TLS | 证书和协议安全检测 |
| 安全头 | HTTP安全响应头检测 |

### 🤖 AI智能分析

- 基于LLM的漏洞深度分析
- 风险评级和CVSS评分
- 修复建议和优先级排序
- 支持多种大模型：OpenAI、Claude、通义千问、豆包、DeepSeek等

### 📊 报告生成

- **HTML报告** - 美观的Web报告
- **JSON报告** - 便于程序处理
- **PDF报告** - 中文PDF文档
- **历史趋势** - 扫描历史和趋势图表

### 🔐 认证支持

- Cookie登录认证
- Bearer Token认证
- Basic认证
- OAuth2认证

### 📈 其他特性

- Web指纹识别
- 敏感目录扫描
- 漏洞库实时更新
- 去重和误报过滤
- 置信度评分

## 安装

```bash
pip install requests fpdf2 matplotlib pillow
```

## 快速开始

### GUI模式（推荐）

```bash
python security_gui_v3.py
```

### 命令行模式

```bash
python security_scan_v3.py https://example.com
```

## 项目结构

```
├── security_gui_v3.py      # GUI主程序
├── security_scan_v3.py     # 扫描引擎
├── auth_manager.py          # 认证管理
├── report_generator.py      # 报告生成
├── llm_analyzer.py         # LLM AI分析
├── vuln_db.json            # 漏洞数据库
├── auth_config.json        # 认证配置
├── llm_config.json         # LLM配置
├── simsun.ttc              # 中文字体
└── reports/                # 扫描报告
```

## 配置说明

### LLM配置

在GUI中点击"LLM配置"按钮，可配置：

- **OpenAI** - ChatGPT
- **Claude** - Anthropic Claude
- **通义千问** - 阿里云
- **豆包** - 字节跳动
- **DeepSeek**
- **Gemini** - Google

### 认证配置

在GUI中点击"认证配置"按钮，可配置：

- **Cookie登录** - 表单认证
- **Bearer Token** - API Token
- **Basic认证** - HTTP Basic
- **OAuth2** - 客户端凭证/密码/授权码模式

## 扫描选项

| 选项 | 说明 |
|-----|------|
| SSL/TLS | 检测HTTPS配置 |
| 安全头 | 检测HTTP响应头 |
| Web指纹 | 识别技术栈 |
| 目录扫描 | 敏感路径检测 |
| SQL注入 | SQL注入漏洞 |
| XSS | 跨站脚本 |
| SSRF | 服务端请求伪造 |
| 命令注入 | 系统命令执行 |
| CSRF | 请求伪造 |
| IDOR | 越权访问 |
| 路径遍历 | 文件读取 |
| 开放重定向 | 重定向漏洞 |
| 敏感信息 | 密钥泄露 |
| AI分析 | LLM深度分析 |

## 使用示例

### 基本扫描

```bash
python security_scan_v3.py https://example.com
```

### 报告输出

扫描完成后自动生成三种格式报告：

- `reports/security_report_*.html`
- `reports/security_report_*.json`
- `reports/security_report_*.pdf`

## 依赖

- Python 3.8+
- requests
- fpdf2
- matplotlib
- pillow
- tkinter (Python内置)

## 许可证

MIT License

## 更新日志

### v3.0.0
- 新增认证支持（Cookie/Token/OAuth）
- 增强检测准确率（基线对比、去重）
- 新增置信度评分
- 新增PDF中文报告
- 新增历史趋势图表

### v2.0.0
- 新增多种漏洞检测
- 添加LLM AI分析
- 添加GUI界面

### v1.0.0
- 初始版本
