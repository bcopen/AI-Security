"""
AI安全测试框架
集成AI分析的安全扫描工具
"""

import json
import re
import ssl
import socket
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


class SecurityScanner:
    """AI安全扫描器"""
    
    def __init__(self):
        self.results = []
        self.vulnerabilities = []
        
        # OWASP Top 10 检查规则
        self.sql_injection_patterns = [
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "'; DROP TABLE users;--", "1' AND '1'='1",
            "1 UNION SELECT NULL--", "' OR ''='"
        ]
        
        self.xss_patterns = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "javascript:alert(1)",
            "<body onload=alert(1)>", "'-alert(1)-'"
        ]
        
        self.sensitive_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{20,}', "API Key"),
            (r'secret["\']?\s*[:=]\s*["\']?[\w-]{20,}', "Secret"),
            (r'password["\']?\s*[:=]\s*["\']?[^\s"\'<]{6,}', "Password"),
            (r'token["\']?\s*[:=]\s*["\']?[\w-]{20,}', "Token"),
            (r'Bearer\s+[\w-]+\.?[\w-]*', "Bearer Token"),
            (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT Token"),
        ]
        
    def scan_url(self, url: str, ai_analysis: bool = True) -> dict:
        """扫描单个URL"""
        print(f"\n{'='*50}")
        print(f"开始安全扫描: {url}")
        print(f"{'='*50}")
        
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "full" if ai_analysis else "basic",
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        }
        
        # 1. SSL/TLS检查
        self.check_ssl(url, results)
        
        # 2. 头部安全检查
        self.check_security_headers(url, results)
        
        # 3. SQL注入测试
        self.test_sql_injection(url, results)
        
        # 4. XSS测试
        self.test_xss(url, results)
        
        # 5. 敏感信息泄露
        self.check_sensitive_data(url, results)
        
        # 6. 目录枚举
        self.enumerate_directories(url, results)
        
        # 7. AI分析
        if ai_analysis:
            ai_findings = self.ai_analyze_results(results)
            results["ai_analysis"] = ai_findings
            
        # 统计
        for finding in results["findings"]:
            severity = finding.get("severity", "info")
            results["severity_counts"][severity] = results["severity_counts"].get(severity, 0) + 1
            
        results["total_findings"] = len(results["findings"])
        
        self.results.append(results)
        
        return results
        
    def check_ssl(self, url: str, results: dict):
        """SSL/TLS安全检查"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                results["findings"].append({
                    "type": "SSL/TLS",
                    "severity": "high",
                    "title": "未使用HTTPS",
                    "description": "网站未使用SSL/TLS加密连接",
                    "recommendation": "启用HTTPS并配置有效的SSL证书"
                })
                return
                
            hostname = parsed.netloc.split(":")[0]
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    # 检查SSL版本
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                        results["findings"].append({
                            "type": "SSL/TLS",
                            "severity": "critical",
                            "title": "过时的SSL/TLS版本",
                            "description": f"使用不安全的协议版本: {version}",
                            "recommendation": "禁用TLS 1.0/1.1和SSLv3，仅启用TLS 1.2/1.3"
                        })
                    else:
                        results["findings"].append({
                            "type": "SSL/TLS",
                            "severity": "info",
                            "title": "SSL/TLS配置正常",
                            "description": f"使用安全协议: {version}",
                            "recommendation": ""
                        })
                        
        except Exception as e:
            results["findings"].append({
                "type": "SSL/TLS",
                "severity": "medium",
                "title": "SSL连接错误",
                "description": str(e),
                "recommendation": "检查SSL证书配置"
            })
            
    def check_security_headers(self, url: str, results: dict):
        """检查安全响应头"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                "Strict-Transport-Security": "HSTS - 强制HTTPS",
                "Content-Security-Policy": "CSP - 内容安全策略",
                "X-Content-Type-Options": "防止MIME类型 sniffing",
                "X-Frame-Options": "防止点击劫持",
                "X-XSS-Protection": "XSS过滤",
                "Referrer-Policy": "引用策略",
                "Permissions-Policy": "权限策略"
            }
            
            missing = []
            for header, desc in security_headers.items():
                if header not in headers:
                    missing.append((header, desc))
                    
            for header, desc in missing:
                results["findings"].append({
                    "type": "Security Headers",
                    "severity": "medium",
                    "title": f"缺少安全头: {header}",
                    "description": f"缺少{desc}响应头",
                    "recommendation": f"添加 {header} 响应头"
                })
                
        except Exception as e:
            pass
            
    def test_sql_injection(self, url: str, results: dict):
        """SQL注入测试"""
        print("  [-] 测试SQL注入...")
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 检查URL参数
        if parsed.query:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            
            for param in params:
                for payload in self.sql_injection_patterns[:3]:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        response = requests.get(test_url, timeout=5, verify=False)
                        
                        # 检测SQL错误特征
                        error_indicators = [
                            "sql syntax", "mysql_fetch", "ORA-", "postgresql",
                            "sqlite3", "unterminated", "syntax error"
                        ]
                        
                        response_lower = response.text.lower()
                        for error in error_indicators:
                            if error in response_lower:
                                results["findings"].append({
                                    "type": "SQL Injection",
                                    "severity": "critical",
                                    "title": f"可能存在SQL注入: {param}",
                                    "description": f"参数 {param} 可能存在SQL注入漏洞",
                                    "payload": payload,
                                    "recommendation": "使用参数化查询或预编译语句"
                                })
                                break
                    except:
                        pass
                        
    def test_xss(self, url: str, results: dict):
        """XSS测试"""
        print("  [-] 测试XSS...")
        
        parsed = urlparse(url)
        
        if parsed.query:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            
            for param in params:
                for payload in self.xss_patterns[:2]:
                    try:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                        response = requests.get(test_url, timeout=5, verify=False)
                        
                        if payload in response.text:
                            results["findings"].append({
                                "type": "XSS",
                                "severity": "high",
                                "title": f"可能存在XSS: {param}",
                                "description": f"参数 {param} 未经转义直接输出",
                                "payload": payload,
                                "recommendation": "对输出进行HTML转义"
                            })
                            break
                    except:
                        pass
                        
    def check_sensitive_data(self, url: str, results: dict):
        """敏感信息检测"""
        print("  [-] 检测敏感信息...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            text = response.text
            
            for pattern, info in self.sensitive_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    results["findings"].append({
                        "type": "Sensitive Data",
                        "severity": "high",
                        "title": f"泄露{info}",
                        "description": f"在页面中发现疑似{info}",
                        "recommendation": "移除敏感信息，使用环境变量"
                    })
                    
        except:
            pass
            
    def enumerate_directories(self, url: str, results: dict):
        """目录枚举"""
        print("  [-] 检查敏感目录...")
        
        common_paths = [
            "/admin", "/api", "/backup", "/config", "/.git",
            "/.env", "/phpinfo.php", "/info.php", "/login",
            "/phpmyadmin", "/wp-admin", "/xmlrpc.php"
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        found_dirs = []
        
        for path in common_paths:
            try:
                response = requests.get(base_url + path, timeout=3, verify=False)
                if response.status_code == 200:
                    found_dirs.append(path)
            except:
                pass
                
        if found_dirs:
            results["findings"].append({
                "type": "Information Disclosure",
                "severity": "medium",
                "title": "发现敏感目录",
                "description": f"发现: {', '.join(found_dirs)}",
                "recommendation": "限制敏感目录访问权限"
            })
            
    def ai_analyze_results(self, results: dict) -> dict:
        """AI分析扫描结果"""
        findings = results.get("findings", [])
        
        if not findings:
            return {"summary": "未发现明显安全问题"}
            
        # 按严重性分类
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        
        # 生成AI建议
        analysis = {
            "risk_level": "高危" if critical or high else ("中危" if medium else "低危"),
            "summary": f"发现 {len(findings)} 个问题，其中 {len(critical)} 个严重问题",
            "prioritized_fixes": [],
            "overall_recommendation": ""
        }
        
        # 优先级排序
        priority_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(findings, key=lambda x: priority_order.index(x.get("severity", "info")))
        
        for f in sorted_findings[:5]:
            analysis["prioritized_fixes"].append({
                "fix": f.get("recommendation", ""),
                "severity": f.get("severity", ""),
                "reason": f.get("title", "")
            })
            
        # 总体建议
        if critical:
            analysis["overall_recommendation"] = "立即修复严重问题，优先处理SQL注入和SSL配置"
        elif high:
            analysis["overall_recommendation"] = "尽快修复高危问题，加强输入验证"
        elif medium:
            analysis["overall_recommendation"] = "计划修复中危问题，完善安全配置"
        else:
            analysis["overall_recommendation"] = "安全状况良好，建议持续监控"
            
        return analysis
        
    def generate_report(self, output_format: str = "html") -> str:
        """生成安全测试报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI安全扫描报告</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #6c757d; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #343a40; color: white; }}
        .severity {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #17a2b8; color: white; }}
        .badge-info {{ background: #6c757d; color: white; }}
        .ai-section {{ background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .recommendation {{ background: #d4edda; padding: 15px; border-radius: 8px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AI安全扫描报告</h1>
        <p>扫描时间: {timestamp}</p>
"""
        
        for result in self.results:
            html += f"""
        <h2>扫描目标: {result['url']}</h2>
        
        <div class="summary">
            <div class="stat">
                <div class="stat-value">{result.get('total_findings', 0)}</div>
                <div>发现问题</div>
            </div>
            <div class="stat">
                <div class="stat-value critical">{result['severity_counts'].get('critical', 0)}</div>
                <div>严重</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{result['severity_counts'].get('high', 0)}</div>
                <div>高危</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{result['severity_counts'].get('medium', 0)}</div>
                <div>中危</div>
            </div>
            <div class="stat">
                <div class="stat-value low">{result['severity_counts'].get('low', 0)}</div>
                <div>低危</div>
            </div>
</div>
"""
            
            # AI分析
            if result.get("ai_analysis"):
                ai = result["ai_analysis"]
                html += f"""
        <div class="ai-section">
            <h3>AI风险分析</h3>
            <p><strong>风险等级:</strong> <span class="{ai.get('risk_level', '')}">{ai.get('risk_level', '')}</span></p>
            <p><strong>分析摘要:</strong> {ai.get('summary', '')}</p>
            <div class="recommendation">
                <strong>AI建议:</strong> {ai.get('overall_recommendation', '')}
            </div>
        </div>
"""
            
            # 详细结果
            html += """
        <h3>详细发现</h3>
        <table>
            <tr>
                <th>严重性</th>
                <th>类型</th>
                <th>标题</th>
                <th>描述</th>
                <th>建议</th>
            </tr>
"""
            
            for f in result.get("findings", []):
                severity = f.get("severity", "info")
                html += f"""
            <tr>
                <td><span class="severity badge-{severity}">{severity.upper()}</span></td>
                <td>{f.get('type', '')}</td>
                <td>{f.get('title', '')}</td>
                <td>{f.get('description', '')[:100]}...</td>
                <td>{f.get('recommendation', '')[:100]}</td>
            </tr>
"""
            
            html += """
        </table>
"""
        
        html += """
    </div>
</body>
</html>"""
        
        # 保存报告
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f"security_report_{timestamp}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return str(report_file)


def quick_scan(url: str) -> dict:
    """快速扫描"""
    scanner = SecurityScanner()
    result = scanner.scan_url(url)
    report = scanner.generate_report()
    return result, report


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python security_scan.py <URL>")
        print("示例: python security_scan.py https://example.com")
        sys.exit(1)
        
    url = sys.argv[1]
    scanner = SecurityScanner()
    result = scanner.scan_url(url)
    report = scanner.generate_report()
    
    print(f"\n{'='*50}")
    print(f"扫描完成!")
    print(f"发现问题: {result['total_findings']}")
    print(f"报告: {report}")
    print(f"{'='*50}")
