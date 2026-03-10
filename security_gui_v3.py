"""
安全测试GUI界面 v3 - 增强版
- 支持更多漏洞类型 (CSRF, IDOR, 路径遍历, 开放重定向)
- 支持漏洞库更新
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import webbrowser
import os
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from security_scan_v3 import EnhancedSecurityScannerV3, VulnerabilityDatabase
from llm_analyzer import LLMAnalyzer
from report_generator import ReportGenerator


"""
安全测试GUI界面 v3 - 增强版
- 支持更多漏洞类型 (CSRF, IDOR, 路径遍历, 开放重定向)
- 支持漏洞库更新
- 支持认证扫描
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import webbrowser
import os
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from security_scan_v3 import EnhancedSecurityScannerV3, VulnerabilityDatabase
from llm_analyzer import LLMAnalyzer
from report_generator import ReportGenerator


class AuthConfigDialog:
    """认证配置对话框"""
    
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("认证配置")
        self.top.geometry("600x500")
        self.top.transient(parent)
        self.top.grab_set()
        
        self.auth_config = {}
        self.load_config()
        self.create_widgets()
        self.top.wait_window()
        
    def load_config(self):
        config_file = Path("auth_config.json")
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.auth_config = json.load(f)
            except:
                self.auth_config = {}
                
    def save_config(self):
        config_file = Path("auth_config.json")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.auth_config, f, indent=2, ensure_ascii=False)
            
    def create_widgets(self):
        main_frame = ttk.Frame(self.top, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="认证类型:", font=("微软雅黑", 11)).pack(anchor=tk.W)
        
        self.auth_type = tk.StringVar(value="none")
        
        type_frame = ttk.Frame(main_frame)
        type_frame.pack(fill=tk.X, pady=5)
        
        types = [
            ("无", "none"),
            ("Cookie登录", "cookie"),
            ("Bearer Token", "token"),
            ("Basic认证", "basic"),
            ("OAuth2", "oauth2")
        ]
        
        for label, value in types:
            ttk.Radiobutton(type_frame, text=label, variable=self.auth_type, 
                          value=value, command=self.on_type_change).pack(side=tk.LEFT, padx=10)
        
        # 配置区域
        self.config_frame = ttk.LabelFrame(main_frame, text="认证配置", padding="15")
        self.config_frame.pack(fill=tk.BOTH, expand=True, pady=15)
        
        self.create_config_fields()
        
        # 按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="保存配置", command=self.save_btn_click).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="测试连接", command=self.test_auth).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清除认证", command=self.clear_auth).pack(side=tk.LEFT, padx=5)
        
        self.lbl_status = ttk.Label(btn_frame, text="", foreground="gray")
        self.lbl_status.pack(side=tk.RIGHT, padx=10)
        
    def create_config_fields(self):
        for widget in self.config_frame.winfo_children():
            widget.destroy()
            
        auth_type = self.auth_type.get()
        
        if auth_type == "none":
            ttk.Label(self.config_frame, text="无需认证").pack()
            return
            
        row = 0
        
        if auth_type == "cookie":
            self.add_field(row, "login_url", "登录URL:", "https://example.com/login")
            self.add_field(row+1, "username", "用户名:", "")
            self.add_field(row+2, "password", "密码:", "", show="*")
            self.add_field(row+3, "cookie_name", "Cookie名称:", "session")
            
        elif auth_type == "token":
            self.add_field(row, "token_url", "Token URL:", "https://example.com/api/token")
            self.add_field(row+1, "username", "用户名:", "")
            self.add_field(row+2, "password", "密码:", "", show="*")
            self.add_field(row+3, "grant_type", "授权类型:", "password")
            
        elif auth_type == "basic":
            self.add_field(row, "username", "用户名:", "")
            self.add_field(row+1, "password", "密码:", "", show="*")
            
        elif auth_type == "oauth2":
            self.add_field(row, "auth_url", "授权URL:", "https://example.com/oauth/authorize")
            self.add_field(row+1, "token_url", "Token URL:", "https://example.com/oauth/token")
            self.add_field(row+2, "client_id", "Client ID:", "")
            self.add_field(row+3, "client_secret", "Client Secret:", "", show="*")
            self.add_field(row+4, "scope", "权限范围:", "read write")
            
    def add_field(self, row, key, label, default="", show=None):
        ttk.Label(self.config_frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=5)
        var = tk.StringVar(value=self.auth_config.get("config", {}).get(key, default))
        entry = ttk.Entry(self.config_frame, textvariable=var, show=show, width=40)
        entry.grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        setattr(self, f"var_{key}", var)
        
    def on_type_change(self):
        self.create_config_fields()
        
    def save_btn_click(self):
        auth_type = self.auth_type.get()
        
        if auth_type == "none":
            self.auth_config = {}
        else:
            config = {}
            for key in dir(self):
                if key.startswith("var_"):
                    field_name = key[4:]
                    config[field_name] = getattr(self, key).get()
                    
            self.auth_config = {
                "type": auth_type,
                "config": config
            }
            
        self.save_config()
        self.lbl_status.config(text="保存成功!", foreground="green")
        
    def test_auth(self):
        self.lbl_status.config(text="测试中...", foreground="blue")
        
        def test_thread():
            try:
                from auth_manager import AuthManager
                manager = AuthManager()
                
                auth_type = self.auth_type.get()
                if auth_type == "none":
                    self.top.after(0, lambda: self.lbl_status.config(text="无需认证", foreground="gray"))
                    return
                    
                config = {}
                for key in dir(self):
                    if key.startswith("var_"):
                        field_name = key[4:]
                        config[field_name] = getattr(self, key).get()
                        
                manager.set_auth(auth_type, config)
                
                # 获取base_url
                base_url = ""
                if auth_type == "cookie":
                    login_url = config.get("login_url", "")
                    if login_url:
                        base_url = "/".join(login_url.split("/")[:3])
                        
                if manager.login(base_url):
                    self.top.after(0, lambda: self.lbl_status.config(text="认证成功!", foreground="green"))
                else:
                    self.top.after(0, lambda: self.lbl_status.config(text="认证失败", foreground="red"))
            except Exception as e:
                self.top.after(0, lambda: self.lbl_status.config(text=f"错误: {str(e)[:30]}", foreground="red"))
                
        threading.Thread(target=test_thread, daemon=True).start()
        
    def clear_auth(self):
        self.auth_config = {}
        self.save_config()
        self.lbl_status.config(text="已清除", foreground="gray")


class LLMConfigDialog:
    """LLM配置对话框"""
    
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("LLM AI配置")
        self.top.geometry("850x600")
        self.top.transient(parent)
        self.top.grab_set()
        
        self.saved_configs = []
        self.load_all_configs()
        self.create_widgets()
        self.top.wait_window()
        
    def load_all_configs(self):
        config_file = Path("llm_configs.json")
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.saved_configs = json.load(f)
            except:
                self.saved_configs = []
                
    def save_all_configs(self):
        config_file = Path("llm_configs.json")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.saved_configs, f, indent=2, ensure_ascii=False)
            
    def create_widgets(self):
        left_frame = ttk.Frame(self.top)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)
        
        ttk.Label(left_frame, text="已配置的大模型:", font=("微软雅黑", 10, "bold")).pack(anchor=tk.W)
        
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.config_listbox = tk.Listbox(list_frame, width=25, height=15)
        self.config_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.config_listbox.bind('<<ListboxSelect>>', self.on_select_config)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.config_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.config_listbox.config(yscrollcommand=scrollbar.set)
        
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="使用", command=self.use_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除", command=self.delete_config).pack(side=tk.LEFT, padx=2)
        
        self.refresh_list()
        
        right_frame = ttk.LabelFrame(self.top, text="配置详情", padding="15")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(right_frame, text="快速选择:").pack(anchor=tk.W, pady=(0, 5))
        
        provider_frame = ttk.Frame(right_frame)
        provider_frame.pack(fill=tk.X, pady=3)
        
        providers = [
            ("OpenAI", "openai"), ("Claude", "claude"), ("DeepSeek", "deepseek"),
            ("豆包", "doubao"), ("通义", "qwen"), ("Gemini", "gemini"),
        ]
        
        for label, value in providers:
            btn = ttk.Button(provider_frame, text=label, width=8,
                           command=lambda v=value, l=label: self.fill_provider(v, l))
            btn.pack(side=tk.LEFT, padx=2, pady=2)
        
        ttk.Label(right_frame, text="提供商:").pack(anchor=tk.W, pady=(10, 3))
        self.entry_provider = ttk.Entry(right_frame)
        self.entry_provider.pack(fill=tk.X)
        
        ttk.Label(right_frame, text="配置名称:").pack(anchor=tk.W, pady=(10, 3))
        self.entry_name = ttk.Entry(right_frame)
        self.entry_name.pack(fill=tk.X)
        
        ttk.Label(right_frame, text="API密钥:").pack(anchor=tk.W, pady=(10, 3))
        self.entry_key = ttk.Entry(right_frame, show="*")
        self.entry_key.pack(fill=tk.X)
        
        ttk.Label(right_frame, text="API地址(可选):").pack(anchor=tk.W, pady=(10, 3))
        self.entry_api_url = ttk.Entry(right_frame)
        self.entry_api_url.pack(fill=tk.X)
        
        self.var_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_frame, text="启用此配置", variable=self.var_enabled).pack(anchor=tk.W, pady=10)
        
        btn_frame2 = ttk.Frame(right_frame)
        btn_frame2.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame2, text="保存配置", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="测试连接", command=self.test_api).pack(side=tk.LEFT, padx=5)
        
        self.lbl_test = ttk.Label(right_frame, text="", foreground="gray")
        self.lbl_test.pack(pady=5)
        
    def refresh_list(self):
        self.config_listbox.delete(0, tk.END)
        for config in self.saved_configs:
            name = config.get("name", config.get("provider", "未命名"))
            self.config_listbox.insert(tk.END, name)
            
    def on_select_config(self, event):
        selection = self.config_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        config = self.saved_configs[idx]
        
        self.entry_provider.delete(0, tk.END)
        self.entry_provider.insert(0, config.get("provider", ""))
        
        self.entry_name.delete(0, tk.END)
        self.entry_name.insert(0, config.get("name", ""))
        
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, config.get("api_key", ""))
        
        self.entry_api_url.delete(0, tk.END)
        self.entry_api_url.insert(0, config.get("api_url", ""))
        
        self.var_enabled.set(config.get("enabled", True))
        
    def fill_provider(self, value, label):
        self.entry_provider.delete(0, tk.END)
        self.entry_provider.insert(0, value)
        if not self.entry_name.get():
            self.entry_name.insert(0, label)
            
    def save_config(self):
        provider = self.entry_provider.get().strip()
        api_key = self.entry_key.get().strip()
        name = self.entry_name.get().strip() or provider
        
        if not provider or not api_key:
            self.lbl_test.config(text="请填写提供商和API密钥", foreground="red")
            return
            
        for i, config in enumerate(self.saved_configs):
            if config.get("provider") == provider:
                self.saved_configs[i] = {
                    "provider": provider,
                    "api_key": api_key,
                    "api_url": self.entry_api_url.get().strip(),
                    "name": name,
                    "enabled": self.var_enabled.get()
                }
                break
        else:
            self.saved_configs.append({
                "provider": provider,
                "api_key": api_key,
                "api_url": self.entry_api_url.get().strip(),
                "name": name,
                "enabled": self.var_enabled.get()
            })
            
        self.save_all_configs()
        self.refresh_list()
        self.lbl_test.config(text="保存成功!", foreground="green")
        
    def use_config(self):
        selection = self.config_listbox.curselection()
        if not selection:
            self.lbl_test.config(text="请先选择一个配置", foreground="red")
            return
            
        idx = selection[0]
        config = self.saved_configs[idx]
        
        current_config = {
            "provider": config.get("provider"),
            "api_key": config.get("api_key"),
            "api_url": config.get("api_url"),
            "enabled": config.get("enabled", True)
        }
        
        with open("llm_config.json", 'w') as f:
            json.dump(current_config, f, indent=2)
            
        self.lbl_test.config(text=f"已切换到: {config.get('name')}", foreground="green")
        
    def delete_config(self):
        selection = self.config_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        del self.saved_configs[idx]
        self.save_all_configs()
        self.refresh_list()
        self.lbl_test.config(text="已删除", foreground="gray")
        
    def test_api(self):
        provider = self.entry_provider.get().strip()
        api_key = self.entry_key.get().strip()
        
        if not api_key:
            self.lbl_test.config(text="请输入API密钥", foreground="red")
            return
            
        self.lbl_test.config(text="测试中...", foreground="blue")
        
        def test_thread():
            try:
                analyzer = LLMAnalyzer(provider=provider, api_key=api_key)
                result = analyzer._call_openai("说'你好'") if provider == "openai" else analyzer._call_claude("说'你好'")
                
                if "error" not in result:
                    self.top.after(0, lambda: self.lbl_test.config(text="连接成功!", foreground="green"))
                else:
                    self.top.after(0, lambda: self.lbl_test.config(text=f"错误: {result.get('error', '未知')}", foreground="red"))
            except Exception as e:
                self.top.after(0, lambda: self.lbl_test.config(text=f"错误: {str(e)[:30]}", foreground="red"))
                
        threading.Thread(target=test_thread, daemon=True).start()


class SecurityGUIv3:
    """安全测试可视化界面 v3"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI安全扫描工具 v3")
        self.root.geometry("1000x820")
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title = ttk.Label(main_frame, text="AI安全扫描工具 v3 (增强版)", font=("微软雅黑", 18, "bold"))
        title.pack(pady=10)
        
        scan_frame = ttk.LabelFrame(main_frame, text="扫描目标", padding="15")
        scan_frame.pack(fill=tk.X, pady=5)
        
        url_frame = ttk.Frame(scan_frame)
        url_frame.pack(fill=tk.X)
        
        ttk.Label(url_frame, text="URL地址:").pack(side=tk.LEFT)
        self.entry_url = ttk.Entry(url_frame, width=60, font=("微软雅黑", 11))
        self.entry_url.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.entry_url.insert(0, "https://")
        
        opt_frame = ttk.LabelFrame(main_frame, text="扫描选项", padding="10")
        opt_frame.pack(fill=tk.X, pady=5)
        
        row1 = ttk.Frame(opt_frame)
        row1.pack(fill=tk.X)
        
        self.var_ssl = tk.BooleanVar(value=True)
        ttk.Checkbutton(row1, text="SSL/TLS", variable=self.var_ssl).pack(side=tk.LEFT, padx=10)
        
        self.var_headers = tk.BooleanVar(value=True)
        ttk.Checkbutton(row1, text="安全头", variable=self.var_headers).pack(side=tk.LEFT, padx=10)
        
        self.var_fingerprint = tk.BooleanVar(value=True)
        ttk.Checkbutton(row1, text="Web指纹", variable=self.var_fingerprint).pack(side=tk.LEFT, padx=10)
        
        self.var_directory = tk.BooleanVar(value=True)
        ttk.Checkbutton(row1, text="目录扫描", variable=self.var_directory).pack(side=tk.LEFT, padx=10)
        
        row2 = ttk.Frame(opt_frame)
        row2.pack(fill=tk.X, pady=5)
        
        self.var_sql = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="SQL注入", variable=self.var_sql).pack(side=tk.LEFT, padx=10)
        
        self.var_xss = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="XSS", variable=self.var_xss).pack(side=tk.LEFT, padx=10)
        
        self.var_ssrf = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="SSRF", variable=self.var_ssrf).pack(side=tk.LEFT, padx=10)
        
        self.var_command = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="命令注入", variable=self.var_command).pack(side=tk.LEFT, padx=10)
        
        row3 = ttk.Frame(opt_frame)
        row3.pack(fill=tk.X, pady=5)
        
        self.var_csrf = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="CSRF", variable=self.var_csrf).pack(side=tk.LEFT, padx=10)
        
        self.var_idor = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="IDOR", variable=self.var_idor).pack(side=tk.LEFT, padx=10)
        
        self.var_path = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="路径遍历", variable=self.var_path).pack(side=tk.LEFT, padx=10)
        
        self.var_redirect = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="开放重定向", variable=self.var_redirect).pack(side=tk.LEFT, padx=10)
        
        self.var_sensitive = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="敏感信息", variable=self.var_sensitive).pack(side=tk.LEFT, padx=10)
        
        self.var_ai = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="AI分析", variable=self.var_ai).pack(side=tk.LEFT, padx=10)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        scan_frame = ttk.Frame(btn_frame)
        scan_frame.pack(fill=tk.X)
        
        self.btn_scan = ttk.Button(scan_frame, text="开始扫描", command=self.start_scan, style="Action.TButton")
        self.btn_scan.pack(side=tk.LEFT, padx=5, ipadx=15)
        
        self.btn_stop = ttk.Button(scan_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(scan_frame, text="快速扫描", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        
        self.btn_llm = ttk.Button(scan_frame, text="LLM配置", command=self.open_llm_config)
        self.btn_llm.pack(side=tk.RIGHT, padx=5)
        
        self.btn_auth = ttk.Button(scan_frame, text="认证配置", command=self.open_auth_config)
        self.btn_auth.pack(side=tk.RIGHT, padx=5)
        
        self.auth_status_var = tk.StringVar(value="认证: 未配置")
        self.lbl_auth = ttk.Label(scan_frame, textvariable=self.auth_status_var, foreground="gray")
        self.lbl_auth.pack(side=tk.RIGHT, padx=10)
        
        self.check_auth_status()
        
        self.btn_update = ttk.Button(scan_frame, text="更新漏洞库", command=self.update_vuln_db)
        self.btn_update.pack(side=tk.RIGHT, padx=5)
        
        self.llm_status_var = tk.StringVar(value="LLM: 未配置")
        self.lbl_llm = ttk.Label(scan_frame, textvariable=self.llm_status_var, foreground="gray")
        self.lbl_llm.pack(side=tk.RIGHT, padx=10)
        
        report_frame = ttk.Frame(btn_frame)
        report_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(report_frame, text="报告:").pack(side=tk.LEFT, padx=5)
        
        self.btn_report = ttk.Button(report_frame, text="HTML报告", command=self.view_html_report, state=tk.DISABLED)
        self.btn_report.pack(side=tk.LEFT, padx=3)
        
        self.btn_json = ttk.Button(report_frame, text="JSON", command=self.view_json_report, state=tk.DISABLED)
        self.btn_json.pack(side=tk.LEFT, padx=3)
        
        self.btn_pdf = ttk.Button(report_frame, text="PDF报告", command=self.view_pdf_report, state=tk.DISABLED)
        self.btn_pdf.pack(side=tk.LEFT, padx=3)
        
        self.btn_trend = ttk.Button(report_frame, text="历史趋势", command=self.view_trend)
        self.btn_trend.pack(side=tk.LEFT, padx=10)
        
        self.check_llm_status()
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        stats_frame = ttk.LabelFrame(main_frame, text="扫描统计", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.lbl_total = ttk.Label(stats_frame, text="总问题: 0", font=("微软雅黑", 11))
        self.lbl_total.pack(side=tk.LEFT, padx=15)
        
        self.lbl_critical = ttk.Label(stats_frame, text="严重: 0", foreground="#ff6b6b", font=("微软雅黑", 11, "bold"))
        self.lbl_critical.pack(side=tk.LEFT, padx=15)
        
        self.lbl_high = ttk.Label(stats_frame, text="高危: 0", foreground="#ffa502", font=("微软雅黑", 11, "bold"))
        self.lbl_high.pack(side=tk.LEFT, padx=15)
        
        self.lbl_medium = ttk.Label(stats_frame, text="中危: 0", foreground="#ffd93d", font=("微软雅黑", 11, "bold"))
        self.lbl_medium.pack(side=tk.LEFT, padx=15)
        
        self.lbl_cvss = ttk.Label(stats_frame, text="CVSS: -", foreground="#4cc9f0", font=("微软雅黑", 11, "bold"))
        self.lbl_cvss.pack(side=tk.RIGHT, padx=15)
        
        self.lbl_risk = ttk.Label(stats_frame, text="风险: -", foreground="#4cc9f0", font=("微软雅黑", 11, "bold"))
        self.lbl_risk.pack(side=tk.RIGHT, padx=15)
        
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=14, font=("Consolas", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X)
        
        self.scan_results = None
        self.report_path = None
        self.report_paths = {}
        
    def log(self, message):
        try:
            if message:
                self.result_text.insert(tk.END, str(message) + "\n")
                self.result_text.see(tk.END)
        except Exception:
            pass
        
    def set_status(self, message):
        self.status_var.set(message)
        self.root.update()
        
    def get_options(self):
        return {
            "ssl": self.var_ssl.get(),
            "security_headers": self.var_headers.get(),
            "fingerprint": self.var_fingerprint.get(),
            "directory_scan": self.var_directory.get(),
            "sql_injection": self.var_sql.get(),
            "xss": self.var_xss.get(),
            "ssrf": self.var_ssrf.get(),
            "command_injection": self.var_command.get(),
            "csrf": self.var_csrf.get(),
            "idor": self.var_idor.get(),
            "path_traversal": self.var_path.get(),
            "open_redirect": self.var_redirect.get(),
            "sensitive_data": self.var_sensitive.get(),
            "ai_analysis": self.var_ai.get()
        }
        
    def start_scan(self):
        url = self.entry_url.get().strip()
        
        if not url:
            messagebox.showwarning("警告", "请输入URL地址")
            return
            
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("警告", "URL必须以http://或https://开头")
            return
        
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress.start(10)
        self.set_status("正在扫描...")
        self.result_text.delete("1.0", tk.END)
        
        # 获取认证配置
        auth_config = self.get_auth_config()
        
        def scan_thread():
            try:
                scanner = EnhancedSecurityScannerV3(auth_config=auth_config)
                self.scanner = scanner
                options = self.get_options()
                result = scanner.scan(url, options)
                
                llm_analyzer = self.get_llm_analyzer()
                if llm_analyzer and result.get("findings"):
                    self.root.after(0, lambda: self.set_status("正在进行LLM深度分析..."))
                    try:
                        llm_result = llm_analyzer.analyze_vulnerabilities(result["findings"], url)
                        if "analysis" in llm_result:
                            result["llm_analysis"] = llm_result["analysis"]
                            self.log("\n[LLM深度分析完成]")
                    except Exception as e:
                        self.log(f"\n[LLM分析失败: {e}]")
                
                self.scan_results = result
                reports = scanner.generate_all_reports()
                self.report_path = reports.get('html', '')
                self.report_paths = reports
                
                self.root.after(0, self.update_results)
                
            except Exception as e:
                import traceback
                self.root.after(0, lambda: messagebox.showerror("错误", str(e) + "\n" + traceback.format_exc()))
                self.root.after(0, lambda: self.btn_scan.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.btn_stop.config(state=tk.DISABLED))
                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.set_status("扫描失败"))
                
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def stop_scan(self):
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.progress.stop()
        self.set_status("扫描已停止")
        self.log("\n扫描已停止")
        
    def update_results(self):
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_report.config(state=tk.NORMAL)
        self.btn_json.config(state=tk.NORMAL)
        self.btn_pdf.config(state=tk.NORMAL)
        
        if not self.scan_results:
            return
            
        result = self.scan_results
        counts = result.get("severity_counts", {})
        
        self.lbl_total.config(text=f"总问题: {result.get('total_findings', 0)}")
        self.lbl_critical.config(text=f"严重: {counts.get('critical', 0)}")
        self.lbl_high.config(text=f"高危: {counts.get('high', 0)}")
        self.lbl_medium.config(text=f"中危: {counts.get('medium', 0)}")
        
        if result.get("ai_analysis"):
            ai = result["ai_analysis"]
            risk = ai.get("risk_level", "-")
            cvss = ai.get("cvss_score", 0.0)
            self.lbl_risk.config(text=f"风险: {risk}")
            self.lbl_cvss.config(text=f"CVSS: {cvss}")
        
        self.log(f"\n{'='*55}")
        self.log(f"扫描完成: {result['url']}")
        self.log(f"{'='*55}")
        
        if result.get("ai_analysis"):
            ai = result["ai_analysis"]
            self.log(f"\n[AI智能分析]")
            self.log(f"  风险等级: {ai.get('risk_level', '')} (CVSS: {ai.get('cvss_score', 0.0)})")
            self.log(f"  {ai.get('summary', '')}")
            self.log(f"\n[修复建议]")
            for rec in ai.get("recommendations", []):
                self.log(f"  - {rec}")
            
        if result.get("llm_analysis"):
            self.log(f"\n{'='*55}")
            self.log(f"[LLM 深度分析]")
            self.log(f"{'='*55}")
            llm_text = result["llm_analysis"]
            for line in llm_text.split('\n')[:30]:
                if line.strip():
                    self.log(f"  {line}")
            
        self.log(f"\n[详细发现]")
        for f in result.get("findings", []):
            severity = f.get("severity", "info").upper()
            self.log(f"[{severity}] {f.get('title', '')} - {f.get('category', '')}")
            
        self.set_status(f"扫描完成 - 发现 {result.get('total_findings', 0)} 个问题")
        
    def quick_scan(self):
        self.entry_url.delete(0, tk.END)
        self.entry_url.insert(0, "https://httpbin.org")
        self.start_scan()
        
    def view_report(self):
        if self.report_path:
            webbrowser.open(self.report_path)
            
    def view_html_report(self):
        if hasattr(self, 'report_paths') and self.report_paths.get('html'):
            webbrowser.open(self.report_paths['html'])
        elif self.report_path:
            webbrowser.open(self.report_path)
        else:
            messagebox.showwarning("警告", "请先完成扫描")
            
    def view_json_report(self):
        if hasattr(self, 'report_paths') and self.report_paths.get('json'):
            import os
            os.startfile(self.report_paths['json']) if os.name == 'nt' else webbrowser.open(self.report_paths['json'])
        else:
            messagebox.showwarning("警告", "请先完成扫描")
            
    def view_pdf_report(self):
        if hasattr(self, 'report_paths') and self.report_paths.get('pdf'):
            import os
            os.startfile(self.report_paths['pdf']) if os.name == 'nt' else webbrowser.open(self.report_paths['pdf'])
        else:
            messagebox.showwarning("警告", "请先完成扫描")
            
    def view_trend(self):
        """查看趋势分析"""
        generator = ReportGenerator()
        history = generator.load_history()
        
        if not history:
            messagebox.showinfo("提示", "暂无扫描历史，请先进行扫描")
            return
            
        trend_html = generator.generate_trend_html(30)
        if trend_html:
            webbrowser.open(trend_html)
        else:
            messagebox.showwarning("警告", "无法生成趋势图表")
            
    def open_llm_config(self):
        dialog = LLMConfigDialog(self.root)
        self.check_llm_status()
        
    def update_vuln_db(self):
        """更新漏洞库"""
        self.set_status("正在检查漏洞库更新...")
        self.btn_update.config(state=tk.DISABLED)
        
        def update_thread():
            try:
                db = VulnerabilityDatabase()
                has_update = db.check_for_updates()
                
                if has_update:
                    self.root.after(0, lambda: messagebox.showinfo("更新", "发现新版本漏洞库，请手动下载更新!"))
                else:
                    self.root.after(0, lambda: messagebox.showinfo("更新", "当前漏洞库已是最新版本"))
                    
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"更新检查失败: {str(e)}"))
            finally:
                self.root.after(0, lambda: self.btn_update.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.set_status("就绪"))
                
        threading.Thread(target=update_thread, daemon=True).start()
        
    def open_auth_config(self):
        """打开认证配置对话框"""
        dialog = AuthConfigDialog(self.root)
        self.check_auth_status()
        
    def check_auth_status(self):
        """检查认证状态"""
        config_file = Path("auth_config.json")
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                auth_type = config.get("type", "none")
                if auth_type != "none":
                    type_names = {
                        "cookie": "Cookie", "token": "Token", 
                        "basic": "Basic", "oauth2": "OAuth2"
                    }
                    self.auth_status_var.set(f"认证: {type_names.get(auth_type, auth_type)} 已配置")
                    self.lbl_auth.config(foreground="green")
                else:
                    self.auth_status_var.set("认证: 未配置")
                    self.lbl_auth.config(foreground="gray")
            except:
                self.auth_status_var.set("认证: 配置错误")
                self.lbl_auth.config(foreground="red")
        else:
            self.auth_status_var.set("认证: 未配置")
            self.lbl_auth.config(foreground="gray")
            
    def get_auth_config(self):
        """获取认证配置"""
        config_file = Path("auth_config.json")
        if config_file.exists():
            try:
                with open(config_file) as f:
                    return json.load(f)
            except:
                return {}
        return {}
        
    def check_llm_status(self):
        config_file = Path("llm_config.json")
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                if config.get("enabled") and config.get("api_key"):
                    provider = config.get("provider", "openai")
                    provider_names = {
                        "openai": "OpenAI", "claude": "Claude", "azure": "Azure OpenAI",
                        "gemini": "Gemini", "qwen": "通义千问", "ernie": "文心一言",
                        "moonshot": "Moonshot", "deepseek": "DeepSeek", "doubao": "豆包"
                    }
                    display_name = provider_names.get(provider, provider)
                    self.llm_status_var.set(f"LLM: {display_name} 已连接")
                    self.lbl_llm.config(foreground="green")
                else:
                    self.llm_status_var.set("LLM: 未启用")
                    self.lbl_llm.config(foreground="gray")
            except:
                self.llm_status_var.set("LLM: 配置错误")
                self.lbl_llm.config(foreground="red")
        else:
            self.llm_status_var.set("LLM: 未配置")
            self.lbl_llm.config(foreground="gray")
            
    def get_llm_analyzer(self):
        config_file = Path("llm_config.json")
        if not config_file.exists():
            return None
            
        try:
            with open(config_file) as f:
                config = json.load(f)
            if config.get("enabled") and config.get("api_key"):
                analyzer = LLMAnalyzer(
                    provider=config.get("provider", "openai"), 
                    api_key=config.get("api_key")
                )
                analyzer.api_url = config.get("api_url", "")
                return analyzer
        except:
            pass
        return None
        
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = SecurityGUIv3()
    app.run()
