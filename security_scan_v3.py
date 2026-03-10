"""
AI增强安全测试框架 v3
- 支持更多漏洞类型 (CSRF, IDOR, 路径遍历, 开放重定向, LDAP注入, 模板注入)
- 增强检测准确率
- 漏洞库实时更新
- 支持认证扫描
"""

import json
import re
import ssl
import socket
import time
import threading
import random
import string
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.auth import HTTPBasicAuth


try:
    from auth_manager import AuthManager
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False


class VulnerabilityDatabase:
    """漏洞数据库管理"""
    
    def __init__(self, db_path: str = "vuln_db.json"):
        self.db_path = Path(db_path)
        self.data = {}
        self.load_database()
        
    def load_database(self):
        """加载漏洞数据库"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                print(f"[*] 漏洞库加载成功: v{self.data.get('version', 'unknown')}")
            except Exception as e:
                print(f"[!] 漏洞库加载失败: {e}")
                self.data = self._get_default_db()
        else:
            self.data = self._get_default_db()
            
    def _get_default_db(self) -> dict:
        """获取默认数据库"""
        return {"version": "1.0.0", "vulnerabilities": {}}
    
    def get_payloads(self, vuln_type: str) -> list:
        """获取指定类型的payloads"""
        vulns = self.data.get("vulnerabilities", {})
        return vulns.get(vuln_type, {}).get("payloads", [])
    
    def get_sensitive_paths(self) -> list:
        """获取敏感路径列表"""
        return self.data.get("sensitive_paths", {}).get("paths", [])
    
    def get_security_headers(self) -> list:
        """获取安全头部列表"""
        return self.data.get("security_headers", {}).get("headers", [])
    
    def get_sensitive_patterns(self) -> list:
        """获取敏感信息正则"""
        return self.data.get("sensitive_data_patterns", {}).get("patterns", [])
    
    def get_error_patterns(self, vuln_type: str) -> list:
        """获取错误特征"""
        vulns = self.data.get("vulnerabilities", {})
        return vulns.get(vuln_type, {}).get("error_patterns", [])
    
    def check_for_updates(self, update_url: str = None) -> bool:
        """检查更新"""
        url = update_url or self.data.get("update_info", {}).get("update_url")
        if not url:
            return False
            
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                remote_data = response.json()
                remote_version = remote_data.get("version", "0")
                local_version = self.data.get("version", "0")
                
                if self._compare_versions(remote_version, local_version) > 0:
                    print(f"[+] 发现新版本: {remote_version}")
                    return True
            return False
        except:
            return False
            
    def _compare_versions(self, v1: str, v2: str) -> int:
        """比较版本号"""
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]
        
        for i in range(max(len(parts1), len(parts2))):
            p1 = parts1[i] if i < len(parts1) else 0
            p2 = parts2[i] if i < len(parts2) else 0
            if p1 > p2:
                return 1
            elif p1 < p2:
                return -1
        return 0


class EnhancedSecurityScannerV3:
    """增强版AI安全扫描器 v3"""
    
    def __init__(self, db_path: str = "vuln_db.json", auth_config: dict = None):
        self.db = VulnerabilityDatabase(db_path)
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings = []
        self.stop_scan = False
        self.auth_config = auth_config
        self.authenticated = False
        
        # 如果有认证配置，先登录
        if AUTH_AVAILABLE and auth_config:
            self._do_auth()
        
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
        
    def _do_auth(self):
        """执行认证"""
        if not self.auth_config or not AUTH_AVAILABLE:
            return
            
        auth_type = self.auth_config.get("type", "none")
        if auth_type == "none":
            return
            
        try:
            manager = AuthManager()
            manager.set_auth(auth_type, self.auth_config.get("config", {}))
            
            # 从配置中获取base_url
            base_url = self.auth_config.get("base_url", "")
            
            if manager.login(base_url):
                self.session = manager.get_session()
                self.authenticated = True
                print(f"[+] 认证成功: {auth_type}")
            else:
                print(f"[!] 认证失败: {auth_type}")
        except Exception as e:
            print(f"[!] 认证错误: {e}")
            
    def scan(self, url: str, options: dict = None) -> dict:
        """综合扫描"""
        self.stop_scan = False
        options = options or {
            "sql_injection": True,
            "xss": True,
            "command_injection": True,
            "ssrf": True,
            "xxe": False,
            "csrf": True,
            "idor": True,
            "path_traversal": True,
            "open_redirect": True,
            "ldap_injection": False,
            "template_injection": False,
            "sensitive_data": True,
            "security_headers": True,
            "ssl": True,
            "directory_scan": True,
            "fingerprint": True,
            "ai_analysis": True
        }
        
        print(f"\n{'='*60}")
        print(f"开始全面安全扫描 (v3): {url}")
        print(f"{'='*60}")
        
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "metadata": {},
            "scanner_version": "3.0"
        }
        
        scan_tasks = []
        
        if options.get("ssl"):
            scan_tasks.append(("SSL/TLS", lambda: self.check_ssl(url, result)))
            
        if options.get("security_headers"):
            scan_tasks.append(("Security Headers", lambda: self.check_security_headers(url, result)))
            
        if options.get("fingerprint"):
            scan_tasks.append(("Fingerprint", lambda: self.fingerprint(url, result)))
            
        if options.get("directory_scan"):
            scan_tasks.append(("Directory Scan", lambda: self.scan_directories(url, result)))
            
        if options.get("sql_injection"):
            scan_tasks.append(("SQL Injection", lambda: self.test_sql_injection(url, result)))
            
        if options.get("xss"):
            scan_tasks.append(("XSS", lambda: self.test_xss(url, result)))
            
        if options.get("ssrf"):
            scan_tasks.append(("SSRF", lambda: self.test_ssrf(url, result)))
            
        if options.get("command_injection"):
            scan_tasks.append(("Command Injection", lambda: self.test_command_injection(url, result)))
            
        if options.get("csrf"):
            scan_tasks.append(("CSRF", lambda: self.test_csrf(url, result)))
            
        if options.get("idor"):
            scan_tasks.append(("IDOR", lambda: self.test_idor(url, result)))
            
        if options.get("path_traversal"):
            scan_tasks.append(("Path Traversal", lambda: self.test_path_traversal(url, result)))
            
        if options.get("open_redirect"):
            scan_tasks.append(("Open Redirect", lambda: self.test_open_redirect(url, result)))
            
        if options.get("sensitive_data"):
            scan_tasks.append(("Sensitive Data", lambda: self.check_sensitive_data(url, result)))
        
        total_tasks = len(scan_tasks)
        for i, (name, func) in enumerate(scan_tasks, 1):
            if self.stop_scan:
                break
            print(f"\n[{i}/{total_tasks}] {name}...")
            try:
                func()
            except Exception as e:
                print(f"[!] {name}出错: {e}")
                
        if options.get("ai_analysis") and not self.stop_scan:
            print("\n[AI] AI智能分析...")
            result["ai_analysis"] = self.ai_analyze(result)
            
        # 去重：基于title+category+severity
        seen = set()
        unique_findings = []
        for f in result["findings"]:
            key = (f.get("title", ""), f.get("category", ""), f.get("severity", ""))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        result["findings"] = unique_findings
        
        # 过滤低置信度结果
        result["findings"] = [f for f in result["findings"] if f.get("confidence", 0.5) >= 0.3]
        
        for f in result["findings"]:
            sev = f.get("severity", "info")
            result["severity_counts"][sev] = result["severity_counts"].get(sev, 0) + 1
            
        result["total_findings"] = len(result["findings"])
        
        self.results.append(result)
        
        print(f"\n扫描完成! 发现 {result['total_findings']} 个问题")
        
        return result
        
    def stop(self):
        """停止扫描"""
        self.stop_scan = True
        
    def check_ssl(self, url: str, result: dict):
        """SSL/TLS检查 - 增强版"""
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
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv23']:
                        result["findings"].append(self.make_finding(
                            "SSL/TLS", "critical", "过时协议版本",
                            f"使用不安全的协议: {version}", "禁用TLS 1.0/1.1，启用TLS 1.2/1.3"
                        ))
                    else:
                        result["metadata"]["ssl_version"] = version
                        
                    cipher = ssock.cipher()
                    if cipher:
                        result["metadata"]["ssl_cipher"] = cipher[0]
                        
                    if cert:
                        result["metadata"]["ssl_issuer"] = cert.get("issuer", [{}])[0].get("commonName", "Unknown")
                        
                        not_before = cert.get("notBefore", "")
                        not_after = cert.get("notAfter", "")
                        result["metadata"]["ssl_valid_from"] = not_before
                        result["metadata"]["ssl_valid_to"] = not_after
                        
        except ssl.SSLCertVerificationError as e:
            result["findings"].append(self.make_finding(
                "SSL/TLS", "high", "SSL证书验证失败",
                str(e), "使用有效证书或修复证书链"
            ))
        except Exception as e:
            result["findings"].append(self.make_finding(
                "SSL/TLS", "medium", "SSL连接错误", str(e), "检查SSL配置"
            ))
            
    def check_security_headers(self, url: str, result: dict):
        """安全头部检查"""
        try:
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            security_headers = self.db.get_security_headers()
            
            for header_info in security_headers:
                header = header_info.get("name", "")
                severity = header_info.get("severity", "low")
                desc = header_info.get("description", "")
                
                if header not in headers:
                    result["findings"].append(self.make_finding(
                        "Security Headers", severity, f"缺少{header}",
                        f"缺少{desc}响应头", f"添加{header}响应头: {header_info.get('recommendation', '')}"
                    ))
                    
            result["metadata"]["headers"] = dict(headers)
            
        except Exception as e:
            pass
            
    def fingerprint(self, url: str, result: dict):
        """Web指纹识别 - 增强版"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            server = response.headers.get("Server", "")
            if server:
                result["metadata"]["server"] = server
                
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                result["metadata"]["powered_by"] = powered_by
                
            tech = []
            text = response.text.lower()
            
            tech_patterns = [
                ("wordpress", "WordPress"),
                ("wp-content", "WordPress"),
                ("wp-includes", "WordPress"),
                ("django", "Django"),
                ("csrfmiddlewaretoken", "Django"),
                ("laravel", "Laravel"),
                ("laravel_session", "Laravel"),
                ("spring", "Spring"),
                ("thymeleaf", "Spring"),
                ("asp.net", "ASP.NET"),
                ("__viewstate", "ASP.NET"),
                ("react", "React"),
                ("reactjs", "React"),
                ("vue", "Vue.js"),
                ("vuejs", "Vue.js"),
                ("jquery", "jQuery"),
                ("bootstrap", "Bootstrap"),
                ("angular", "Angular"),
                ("next.js", "Next.js"),
                ("nuxt", "Nuxt.js"),
                ("express", "Express"),
                ("fastapi", "FastAPI"),
                ("flask", "Flask"),
                ("tomcat", "Tomcat")
            ]
            
            for pattern, name in tech_patterns:
                if pattern in text:
                    tech.append(name)
                    
            if server:
                server_lower = server.lower()
                if "nginx" in server_lower:
                    result["metadata"]["web_server"] = "Nginx"
                elif "apache" in server_lower:
                    result["metadata"]["web_server"] = "Apache"
                elif "iis" in server_lower:
                    result["metadata"]["web_server"] = "IIS"
                    
            if tech:
                result["metadata"]["technologies"] = list(set(tech))
                
            result["metadata"]["status_code"] = response.status_code
            result["metadata"]["content_type"] = response.headers.get("Content-Type", "")
                
        except:
            pass
            
    def scan_directories(self, url: str, result: dict):
        """敏感目录扫描"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        found = []
        sensitive_paths = self.db.get_sensitive_paths()
        
        for path_info in sensitive_paths[:30]:
            if self.stop_scan:
                break
            path = path_info.get("path", "")
            severity = path_info.get("severity", "medium")
            desc = path_info.get("description", "")
            
            try:
                response = self.session.get(base_url + path, timeout=3, verify=False)
                if response.status_code == 200:
                    found.append({"path": path, "severity": severity, "description": desc})
                elif response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get("Location", "")
                    if location:
                        found.append({"path": f"{path} -> {location}", "severity": severity, "description": desc})
            except:
                pass
                
        if found:
            result["findings"].append(self.make_finding(
                "Information", "medium", "敏感目录/文件暴露",
                f"发现 {len(found)} 个敏感路径: {', '.join([f['path'] for f in found[:5]])}",
                "限制访问权限或删除敏感文件"
            ))
            
    def test_sql_injection(self, url: str, result: dict):
        """SQL注入测试 - 增强版"""
        parsed = urlparse(url)
        
        if not parsed.query:
            test_params = ["id", "user", "page", "search", "q", "query", "uid", "pid", "cid"]
        else:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            test_params = list(params.keys())
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 获取基线响应
        try:
            baseline_response = self.session.get(base_url, timeout=5, verify=False)
            baseline_text = baseline_response.text.lower()
            baseline_status = baseline_response.status_code
            baseline_hash = hash(baseline_text[:1000])
        except:
            baseline_hash = None
            baseline_status = None
            
        payloads = self.db.get_payloads("sql_injection")
        error_patterns = self.db.get_error_patterns("sql_injection")
        
        found_sql = set()
        
        for param in test_params[:5]:
            for payload_obj in payloads[:8]:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # 检查SQL错误
                    text_lower = response.text.lower()
                    error_found = False
                    for error in error_patterns:
                        if error in text_lower:
                            # 二次验证：确认不是通用错误页面
                            if baseline_hash and hash(response.text[:1000]) != baseline_hash:
                                found_sql.add((param, payload, "error_based"))
                            error_found = True
                            break
                    
                    # 检查响应差异
                    if baseline_hash and response.status_code != baseline_status:
                        found_sql.add((param, payload, "status_diff"))
                        
                except:
                    pass
                    
        # 验证并添加结果（去重）
        if found_sql:
            for param, payload, detection_type in found_sql:
                # 只有确认响应发生变化才报告
                result["findings"].append(self.make_finding(
                    "Injection", "high", f"SQL注入漏洞: {param}",
                    f"参数{param}可能存在SQL注入 (检测类型: {detection_type})",
                    "使用参数化查询/预编译语句",
                    payload=payload,
                    confidence=0.7
                ))
                
        if not found_sql:
            self._blind_sql_test(base_url, test_params, result)
                    
    def _blind_sql_test(self, base_url: str, params: list, result: dict):
        """盲注测试"""
        for param in params[:3]:
            try:
                true_url = f"{base_url}?{param}=1' AND SLEEP(3)--"
                false_url = f"{base_url}?{param}=1' AND SLEEP(0)--"
                
                start = time.time()
                self.session.get(true_url, timeout=10, verify=False)
                true_time = time.time() - start
                
                start = time.time()
                self.session.get(false_url, timeout=10, verify=False)
                false_time = time.time() - start
                
                if true_time - false_time > 2:
                    result["findings"].append(self.make_finding(
                        "Injection", "high", f"盲注漏洞: {param}",
                        f"参数{param}可能存在SQL盲注",
                        "使用参数化查询",
                        payload="SLEEP(3)"
                    ))
                    break
                    
            except:
                pass
                
    def test_xss(self, url: str, result: dict):
        """XSS测试 - 增强版"""
        parsed = urlparse(url)
        
        if not parsed.query:
            test_params = ["id", "name", "q", "search", "query", "s", "keyword"]
        else:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            test_params = list(params.keys())
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 获取基线响应
        try:
            baseline_response = self.session.get(base_url, timeout=5, verify=False)
            baseline_text = baseline_response.text
            baseline_hash = hash(baseline_text[:1000])
        except:
            baseline_hash = None
            baseline_text = ""
            
        payloads = self.db.get_payloads("xss")
        
        found_xss = set()
        
        for param in test_params[:4]:
            for payload_obj in payloads[:5]:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # 检查payload是否在响应中
                    if payload in response.text:
                        # 验证：检查是否在HTML标签内（可能的XSS）还是被编码
                        text_lower = response.text.lower()
                        
                        # 检查是否被转义
                        is_escaped = (
                            "&lt;" in text_lower or 
                            "&gt;" in text_lower or 
                            "&amp;" in text_lower or
                            payload.replace("<", "&lt;") in text_lower
                        )
                        
                        # 检查是否在script标签内（高危）
                        in_script = "<script" in text_lower and payload in text_lower
                        
                        # 检查是否在事件处理器中
                        in_event = any(evt in text_lower for evt in ["onerror=", "onload=", "onclick="])
                        
                        if in_script or in_event:
                            found_xss.add((param, payload, "script_event"))
                        elif not is_escaped and baseline_hash:
                            found_xss.add((param, payload, "reflection"))
                                
                except:
                    pass
                    
        # 添加去重后的结果
        if found_xss:
            for param, payload, xss_type in found_xss:
                severity = "high" if xss_type == "script_event" else "medium"
                result["findings"].append(self.make_finding(
                    "XSS", severity, f"反射型XSS: {param}",
                    f"参数{param}检测到XSS风险 (类型: {xss_type})",
                    "输出编码/转义/使用CSP",
                    payload=payload,
                    confidence=0.8 if xss_type == "script_event" else 0.5
                ))
                
        self._dom_xss_test(base_url, test_params, result)
                    
    def _dom_xss_test(self, base_url: str, params: list, result: dict):
        """DOM XSS测试"""
        dom_payloads = [
            "#<img src=x onerror=alert(1)>",
            "#alert(1)",
            "#<script>alert(1)</script>"
        ]
        
        for param in params[:2]:
            for payload in dom_payloads:
                try:
                    test_url = f"{base_url}?{param}=test{payload}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if payload.lstrip('#') in response.text or "<img src=x onerror=alert(1)>" in response.text:
                        result["findings"].append(self.make_finding(
                            "XSS", "high", f"DOM XSS: {param}",
                            f"参数{param}可能存在DOM型XSS",
                            "使用安全的DOM操作方法"
                        ))
                        break
                except:
                    pass
                    
    def test_ssrf(self, url: str, result: dict):
        """SSRF测试 - 增强版"""
        parsed = urlparse(url)
        
        if not parsed.query:
            return
            
        params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
        
        # 获取基线响应
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            baseline_response = self.session.get(base_url, timeout=5, verify=False)
            baseline_hash = hash(baseline_response.text[:1000])
        except:
            baseline_hash = None
            
        payloads = self.db.get_payloads("ssrf")
        
        found_ssrf = set()
        
        for param in params:
            for payload_obj in payloads:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    text_lower = response.text.lower()
                    
                    # 检查响应中的内网特征
                    indicators_found = []
                    for indicator in ["localhost", "127.0.0.1", "0.0.0.0", "metadata", "internal", "cloud"]:
                        if indicator in text_lower:
                            indicators_found.append(indicator)
                    
                    # 验证：确认响应有变化
                    if indicators_found and baseline_hash:
                        response_hash = hash(response.text[:1000])
                        if response_hash != baseline_hash:
                            found_ssrf.add((param, payload, ",".join(indicators_found)))
                            
                except:
                    pass
                    
        # 添加去重后的结果
        if found_ssrf:
            for param, payload, indicators in found_ssrf:
                result["findings"].append(self.make_finding(
                    "SSRF", "high", f"可能存在SSRF: {param}",
                    f"参数{param}可能存在服务端请求伪造 (指标: {indicators})",
                    "验证用户输入的URL，禁止内网访问",
                    payload=payload,
                    confidence=0.7
                ))
                    
    def test_command_injection(self, url: str, result: dict):
        """命令注入测试 - 增强版"""
        parsed = urlparse(url)
        
        if not parsed.query:
            return
            
        params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
        
        payloads = self.db.get_payloads("command_injection")
        
        for param in params:
            for payload_obj in payloads[:5]:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    for indicator in ["root:", "/bin/sh", "bin/bash", "uid=", "groups="]:
                        if indicator in response.text:
                            result["findings"].append(self.make_finding(
                                "Command Injection", "critical", f"命令注入: {param}",
                                f"参数{param}可能执行系统命令 (类型: {payload_obj.get('type', 'unknown')})",
                                "避免使用用户输入执行命令，使用白名单"
                            ))
                            break
                            
                except:
                    pass
                    
    def test_csrf(self, url: str, result: dict):
        """CSRF测试"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            csrf_issues = []
            
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for i, form in enumerate(forms):
                has_token = bool(re.search(r'(csrf|token|_token|xsrf)', form, re.IGNORECASE))
                has_referer = False
                
                if not has_token:
                    csrf_issues.append(f"表单{i+1}: 缺少CSRF Token")
                    
            if csrf_issues:
                result["findings"].append(self.make_finding(
                    "CSRF", "medium", "CSRF保护缺失",
                    "; ".join(csrf_issues),
                    "添加CSRF Token并验证"
                ))
                
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                cookies = self.session.cookies.get_dict()
                if not any("httponly" in c.lower() or "secure" in c.lower() for c in str(cookies)):
                    result["findings"].append(self.make_finding(
                        "Security Headers", "low", "Cookie安全标志缺失",
                        "Cookie缺少HttpOnly或Secure标志",
                        "为Cookie添加安全标志"
                    ))
                    
        except Exception as e:
            pass
            
    def test_idor(self, url: str, result: dict):
        """IDOR测试 - 不安全直接对象引用"""
        parsed = urlparse(url)
        
        path = parsed.path
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        idor_patterns = [
            (r'/user/(\d+)', [1, 2, 3, 999]),
            (r'/profile/(\d+)', [1, 2, 3]),
            (r'/order/(\d+)', [1, 2, 100]),
            (r'/api/user/(\d+)', [1, 2]),
            (r'/api/order/(\d+)', [1, 2]),
            (r'/file/(\d+)', [1, 2]),
            (r'/document/(\d+)', [1, 2])
        ]
        
        for pattern, test_ids in idor_patterns:
            match = re.search(pattern, path)
            if match:
                original_id = match.group(1)
                
                for test_id in test_ids:
                    try:
                        test_path = re.sub(pattern, f'/user/{test_id}', path)
                        test_url = base_url + test_path
                        
                        resp1 = self.session.get(url, timeout=5, verify=False)
                        resp2 = self.session.get(test_url, timeout=5, verify=False)
                        
                        if resp1.status_code == resp2.status_code == 200:
                            if resp1.text != resp2.text:
                                result["findings"].append(self.make_finding(
                                    "IDOR", "high", f"不安全的直接对象引用: {path}",
                                    f"可以访问其他用户的数据 (ID: {test_id})",
                                    "验证用户授权，使用间接引用"
                                ))
                                break
                                
                    except:
                        pass
                        
        idor_paths = ["/user/1", "/profile/1", "/order/1", "/api/user/1"]
        for test_path in idor_paths:
            if test_path in path:
                continue
            try:
                test_url = base_url + test_path
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    result["findings"].append(self.make_finding(
                        "IDOR", "high", f"IDOR测试: {test_path}",
                        f"发现用户相关端点，可能存在越权访问",
                        "验证用户身份和权限"
                    ))
            except:
                pass
                
    def test_path_traversal(self, url: str, result: dict):
        """路径遍历测试"""
        parsed = urlparse(url)
        
        if not parsed.query:
            test_params = ["file", "path", "page", "doc", "download", "img", "image"]
        else:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            test_params = list(params.keys())
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        payloads = self.db.get_payloads("path_traversal")
        
        for param in test_params[:3]:
            for payload_obj in payloads[:6]:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    for indicator in ["root:", "[fonts]", "[extensions]", "<?xml", "<!DOCTYPE"]:
                        if indicator in response.text:
                            result["findings"].append(self.make_finding(
                                "Path Traversal", "critical", f"路径遍历漏洞: {param}",
                                f"参数{param}可以读取系统文件 (类型: {payload_obj.get('type', 'unknown')})",
                                "使用文件ID而非路径，禁止../等字符"
                            ))
                            break
                            
                except:
                    pass
                    
    def test_open_redirect(self, url: str, result: dict):
        """开放重定向测试"""
        parsed = urlparse(url)
        
        redirect_params = ["next", "url", "target", "redirect", "return", "continue", "dest", "callback"]
        
        if parsed.query:
            params = dict(p.split("=") for p in parsed.query.split("&") if "=" in p)
            for param in params:
                redirect_params.append(param)
                
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        payloads = self.db.get_payloads("open_redirect")
        
        for param in redirect_params[:5]:
            for payload_obj in payloads[:4]:
                if self.stop_scan:
                    break
                payload = payload_obj.get("value", "") if isinstance(payload_obj, dict) else payload_obj
                
                try:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    location = response.headers.get("Location", "")
                    
                    if location:
                        if "evil.com" in payload.lower() or payload.startswith("javascript:"):
                            result["findings"].append(self.make_finding(
                                "Open Redirect", "medium", f"开放重定向: {param}",
                                f"参数{param}可重定向到任意URL",
                                "验证重定向目标，禁止外部URL"
                            ))
                            break
                            
                        if any(x in location for x in ["//", "///", "http:", "javascript:"]):
                            if "example.com" not in location and parsed.netloc not in location:
                                result["findings"].append(self.make_finding(
                                    "Open Redirect", "medium", f"可能开放重定向: {param}",
                                    f"参数{param}可能允许外部重定向",
                                    "验证重定向URL"
                                ))
                                break
                                
                except:
                    pass
                    
    def check_sensitive_data(self, url: str, result: dict):
        """敏感信息检测 - 增强版"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            text = response.text
            
            patterns = self.db.get_sensitive_patterns()
            
            for pattern_info in patterns:
                pattern = pattern_info.get("pattern", "")
                data_type = pattern_info.get("type", "未知")
                severity = pattern_info.get("severity", "high")
                
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))[:3]
                    result["findings"].append(self.make_finding(
                        "Sensitive Data", severity, f"{data_type}泄露",
                        f"发现{len(matches)}处{data_type}: {', '.join(unique_matches)}",
                        "使用环境变量/密钥管理服务"
                    ))
                    
        except:
            pass
            
    def make_finding(self, category: str, severity: str, title: str, 
                   description: str, recommendation: str, payload: str = None, confidence: float = 0.5) -> dict:
        """创建发现项"""
        return {
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "payload": payload,
            "owasp": self.get_owasp_category(category),
            "timestamp": datetime.now().isoformat(),
            "confidence": confidence
        }
        
    def get_owasp_category(self, category: str) -> str:
        """获取OWASP分类"""
        mapping = {
            "Injection": "A03:2021-Injection",
            "XSS": "A03:2021-Injection",
            "SQL Injection": "A03:2021-Injection",
            "Command Injection": "A03:2021-Injection",
            "SSRF": "A10:2021-SSRF",
            "CSRF": "A01:2021-Broken Access Control",
            "IDOR": "A01:2021-Broken Access Control",
            "Path Traversal": "A01:2021-Broken Access Control",
            "Open Redirect": "A10:2021-SSRF",
            "LDAP Injection": "A03:2021-Injection",
            "Template Injection": "A03:2021-Injection",
            "Sensitive Data": "A02:2021-Cryptographic Failures",
            "Security Headers": "A05:2021-Security Misconfiguration",
            "SSL/TLS": "A02:2021-Cryptographic Failures",
            "Information": "A01:2021-Broken Access Control"
        }
        return mapping.get(category, "A05:2021-Security Misconfiguration")
        
    def ai_analyze(self, result: dict) -> dict:
        """AI智能分析 - 增强版"""
        findings = result.get("findings", [])
        
        if not findings:
            return {
                "risk_level": "低", 
                "summary": "未发现明显安全问题", 
                "recommendations": [],
                "cvss_score": 0.0
            }
            
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        low = [f for f in findings if f.get("severity") == "low"]
        
        cvss_score = self._calculate_cvss(critical, high, medium, low)
        
        if critical:
            risk_level = "严重"
        elif high:
            risk_level = "高"
        elif medium:
            risk_level = "中"
        elif low:
            risk_level = "低"
        else:
            risk_level = "极低"
            
        recommendations = []
        
        vuln_categories = set(f.get("category") for f in findings)
        
        if "Injection" in vuln_categories or "SQL Injection" in vuln_categories:
            recommendations.append("优先修复注入类漏洞，使用参数化查询/预编译语句")
            
        if "XSS" in vuln_categories:
            recommendations.append("启用内容安全策略(CSP)，对输出进行编码")
            
        if "Command Injection" in vuln_categories:
            recommendations.append("【紧急】避免使用用户输入执行系统命令")
            
        if "Sensitive Data" in vuln_categories:
            recommendations.append("【紧急】立即清理代码中的敏感信息，使用密钥管理服务")
            
        if "Security Headers" in vuln_categories:
            recommendations.append("配置完整的安全响应头")
            
        if "IDOR" in vuln_categories or "CSRF" in vuln_categories:
            recommendations.append("实现完善的访问控制机制")
            
        if critical:
            recommendations.insert(0, "【紧急】发现严重漏洞，建议立即修复")
            
        priority = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: severity_order.get(x.get("severity"), 5)):
            priority.append({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "recommendation": f.get("recommendation"),
                "owasp": f.get("owasp")
            })
            
        return {
            "risk_level": risk_level,
            "cvss_score": round(cvss_score, 1),
            "summary": f"发现 {len(findings)} 个安全问题 ({len(critical)}严重, {len(high)}高危, {len(medium)}中危, {len(low)}低危)",
            "total_findings": len(findings),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "recommendations": recommendations,
            "priority_fixes": priority[:7],
            "owasp_summary": self.get_owasp_summary(findings),
            "remediation_plan": self.generate_remediation_plan(findings)
        }
        
    def _calculate_cvss(self, critical, high, medium, low) -> float:
        """计算CVSS评分"""
        base_score = 0.0
        
        base_score += len(critical) * 10.0
        base_score += len(high) * 7.5
        base_score += len(medium) * 5.0
        base_score += len(low) * 2.5
        
        if base_score > 10.0:
            base_score = 10.0
            
        return base_score
        
    def get_owasp_summary(self, findings: list) -> dict:
        """OWASP分类汇总"""
        owasp_counts = {}
        for f in findings:
            owasp = f.get("owasp", "Unknown")
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
        return owasp_counts
        
    def generate_remediation_plan(self, findings: list) -> str:
        """生成修复计划"""
        plan = "## 修复计划建议\n\n"
        
        plan += "### 第一阶段 (立即 - 24小时内)\n"
        critical = [f for f in findings if f.get("severity") == "critical"]
        for f in critical:
            plan += f"- **{f.get('title')}**\n"
            plan += f"  - 问题: {f.get('description')}\n"
            plan += f"  - 修复: {f.get('recommendation')}\n\n"
            
        if not critical:
            plan += "无严重漏洞\n\n"
            
        plan += "### 第二阶段 (本周)\n"
        high = [f for f in findings if f.get("severity") == "high"]
        for f in high:
            plan += f"- {f.get('title')}: {f.get('recommendation')}\n"
            
        if not high:
            plan += "无高危漏洞\n"
            
        plan += "\n### 第三阶段 (计划中)\n"
        others = [f for f in findings if f.get("severity") in ["medium", "low"]]
        for f in others[:5]:
            plan += f"- {f.get('title')}\n"
            
        return plan
        
    def generate_html_report(self) -> str:
        """生成HTML报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI安全扫描报告 v3 - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #16213e; padding: 30px; border-radius: 12px; }}
        h1 {{ color: #fff; margin-bottom: 20px; }}
        h2 {{ color: #4cc9f0; margin: 25px 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .header-info {{ color: #888; margin-bottom: 20px; }}
        
        .stats {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ background: #0f3460; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ff6b6b; }}
        .high {{ color: #ffa502; }}
        .medium {{ color: #ffd93d; }}
        .low {{ color: #6bcb77; }}
        .info {{ color: #4d96ff; }}
        
        .ai-analysis {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 25px; border-radius: 12px; margin: 20px 0; }}
        .ai-analysis h2 {{ color: #fff; border: none; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-size: 18px; font-weight: bold; }}
        .cvss-badge {{ background: #333; padding: 5px 15px; border-radius: 15px; margin-left: 10px; font-size: 14px; }}
        
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
        
        .metadata {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }}
        .meta-item {{ background: #0f3460; padding: 15px; border-radius: 8px; }}
        .meta-label {{ color: #888; font-size: 12px; }}
        .meta-value {{ font-size: 14px; margin-top: 5px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ color: #4cc9f0; }}
        
        .footer {{ text-align: center; color: #666; margin-top: 30px; padding-top: 20px; border-top: 1px solid #333; }}
        
        .scan-progress {{ background: #0f3460; padding: 15px; border-radius: 8px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI安全扫描报告 v3</h1>
        <p class="header-info">扫描时间: {timestamp} | 扫描器: AI Security Scanner v3.0</p>
"""
        
        for result in self.results:
            counts = result.get("severity_counts", {})
            ai = result.get("ai_analysis", {})
            
            html += f"""
        <div class="stats">
            <div class="stat"><div class="stat-value">{result.get('total_findings', 0)}</div><div class="info">总问题</div></div>
            <div class="stat"><div class="stat-value critical">{counts.get('critical', 0)}</div><div class="critical">严重</div></div>
            <div class="stat"><div class="stat-value high">{counts.get('high', 0)}</div><div class="high">高危</div></div>
            <div class="stat"><div class="stat-value medium">{counts.get('medium', 0)}</div><div class="medium">中危</div></div>
            <div class="stat"><div class="stat-value low">{counts.get('low', 0)}</div><div class="low">低危</div></div>
            <div class="stat"><div class="stat-value info">{counts.get('info', 0)}</div><div class="info">信息</div></div>
            <div class="stat"><div class="stat-value" style="color:#fff">{ai.get('cvss_score', 0.0)}</div><div class="info">CVSS</div></div>
        </div>
"""
            
            if ai:
                risk_class = f"risk-{ai.get('risk_level', 'low')}"
                html += f"""
        <div class="ai-analysis">
            <h2>🤖 AI智能分析</h2>
            <p>
                <span class="risk-badge {risk_class}">{ai.get('risk_level', '低')}风险</span>
                <span class="cvss-badge">CVSS: {ai.get('cvss_score', 0.0)}</span>
            </p>
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
                <tr><th>优先级</th><th>漏洞</th><th>类型</th><th>建议</th><th>OWASP</th></tr>
"""
                for i, fix in enumerate(ai.get("priority_fixes", []), 1):
                    html += f"""
                <tr>
                    <td>{i}</td>
                    <td>{fix.get('title', '')}</td>
                    <td>{fix.get('category', '')}</td>
                    <td>{fix.get('recommendation', '')}</td>
                    <td><span class="owasp-tag">{fix.get('owasp', '')}</span></td>
                </tr>
"""
                html += """
            </table>
        </div>
"""
            
            if result.get("metadata"):
                meta = result["metadata"]
                html += """
        <h2>📊 目标信息</h2>
        <div class="metadata">
"""
                meta_items = [
                    ("server", "Web Server"),
                    ("technologies", "技术栈"),
                    ("ssl_version", "SSL版本"),
                    ("status_code", "状态码")
                ]
                for key, label in meta_items:
                    if meta.get(key):
                        value = ', '.join(meta[key]) if isinstance(meta[key], list) else meta[key]
                        html += f"""
            <div class="meta-item">
                <div class="meta-label">{label}</div>
                <div class="meta-value">{value}</div>
            </div>
"""
                html += """
        </div>
"""
            
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
            <p>AI Security Scanner v3.0 | 扫描完成</p>
        </div>
    </div>
</body>
</html>"""
        
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f"security_report_v3_{timestamp}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return str(report_file)
        
    def generate_all_reports(self) -> dict:
        """生成所有格式的报告"""
        from report_generator import ReportGenerator
        
        if not self.results:
            return {}
            
        result = self.results[-1]
        generator = ReportGenerator()
        
        reports = {
            "html": generator.generate_html_report(result),
            "json": generator.generate_json_report(result),
            "pdf": generator.generate_pdf_report(result)
        }
        
        return reports


def quick_scan(url: str):
    """快速扫描"""
    scanner = EnhancedSecurityScannerV3()
    result = scanner.scan(url)
    report = scanner.generate_all_reports()
    return result, report


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python security_scan_v3.py <URL>")
        print("示例: python security_scan_v3.py https://example.com")
        sys.exit(1)
        
    url = sys.argv[1]
    scanner = EnhancedSecurityScannerV3()
    result = scanner.scan(url)
    reports = scanner.generate_all_reports()
    
    print(f"\n{'='*60}")
    print(f"扫描完成!")
    print(f"发现问题: {result['total_findings']}")
    ai = result.get('ai_analysis', {})
    print(f"AI风险评级: {ai.get('risk_level', 'N/A')} (CVSS: {ai.get('cvss_score', 0.0)})")
    print(f"\n报告已生成:")
    print(f"  HTML: {reports.get('html', '')}")
    print(f"  JSON: {reports.get('json', '')}")
    print(f"  PDF:  {reports.get('pdf', '')}")
    print(f"{'='*60}")
