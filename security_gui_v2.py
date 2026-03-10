"""
安全测试GUI界面 v2 - 增强版
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
from security_scan_v2 import EnhancedSecurityScanner
from llm_analyzer import LLMAnalyzer


class LLMConfigDialog:
    """LLM配置对话框 - 支持多个配置"""
    
    def __init__(self, parent):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("LLM AI配置")
        self.top.geometry("850x600")
        self.top.transient(parent)
        self.top.grab_set()
        
        self.saved_configs = []  # 保存的配置列表
        self.load_all_configs()
        self.create_widgets()
        
        self.top.wait_window()
        
    def load_all_configs(self):
        """加载所有保存的配置"""
        config_file = Path("llm_configs.json")
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.saved_configs = json.load(f)
            except:
                self.saved_configs = []
                
    def save_all_configs(self):
        """保存所有配置"""
        config_file = Path("llm_configs.json")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.saved_configs, f, indent=2, ensure_ascii=False)
            
    def create_widgets(self):
        """创建组件"""
        # 左侧: 已保存的配置列表
        left_frame = ttk.Frame(self.top)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)
        
        ttk.Label(left_frame, text="已配置的大模型:", font=("微软雅黑", 10, "bold")).pack(anchor=tk.W)
        
        # 配置列表
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.config_listbox = tk.Listbox(list_frame, width=25, height=15)
        self.config_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.config_listbox.bind('<<ListboxSelect>>', self.on_select_config)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.config_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.config_listbox.config(yscrollcommand=scrollbar.set)
        
        # 按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="使用", command=self.use_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除", command=self.delete_config).pack(side=tk.LEFT, padx=2)
        
        self.refresh_list()
        
        # 右侧: 配置编辑区
        right_frame = ttk.LabelFrame(self.top, text="配置详情", padding="15")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 提供商快速选择
        ttk.Label(right_frame, text="快速选择:").pack(anchor=tk.W, pady=(0, 5))
        
        provider_frame = ttk.Frame(right_frame)
        provider_frame.pack(fill=tk.X, pady=3)
        
        providers = [
            ("OpenAI", "openai"),
            ("Claude", "claude"), 
            ("DeepSeek", "deepseek"),
            ("豆包", "doubao"),
            ("通义", "qwen"),
            ("Gemini", "gemini"),
        ]
        
        for label, value in providers:
            btn = ttk.Button(provider_frame, text=label, width=8,
                           command=lambda v=value: self.select_provider(v))
            btn.pack(side=tk.LEFT, padx=2)
        
        # 提供商输入
        ttk.Label(right_frame, text="AI提供商:").pack(anchor=tk.W, pady=(10, 5))
        self.entry_provider = ttk.Entry(right_frame, width=40)
        self.entry_provider.pack(fill=tk.X)
        
        # API密钥
        ttk.Label(right_frame, text="API密钥:").pack(anchor=tk.W, pady=(10, 5))
        self.entry_key = ttk.Entry(right_frame, width=40, show="*")
        self.entry_key.pack(fill=tk.X)
        
        # API地址
        ttk.Label(right_frame, text="API地址(可选):").pack(anchor=tk.W, pady=(10, 5))
        self.entry_api_url = ttk.Entry(right_frame, width=40)
        self.entry_api_url.pack(fill=tk.X)
        
        # 配置名称
        ttk.Label(right_frame, text="配置名称(用于识别):").pack(anchor=tk.W, pady=(10, 5))
        self.entry_name = ttk.Entry(right_frame, width=40)
        self.entry_name.pack(fill=tk.X)
        
        # 测试连接
        test_frame = ttk.Frame(right_frame)
        test_frame.pack(fill=tk.X, pady=15)
        
        ttk.Button(test_frame, text="测试连接", command=self.test_api).pack(side=tk.LEFT, padx=5)
        self.lbl_test = ttk.Label(test_frame, text="", foreground="gray")
        self.lbl_test.pack(side=tk.LEFT, padx=10)
        
        # 保存按钮
        save_frame = ttk.Frame(right_frame)
        save_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(save_frame, text="保存配置", command=self.add_new_config).pack(side=tk.LEFT, padx=5)
        
        # 启用选项
        self.var_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_frame, text="启用LLM深度分析", variable=self.var_enabled).pack(anchor=tk.W, pady=15)
        
        # 底部按钮 - 使用两个Frame分开左右
        bottom_frame = ttk.Frame(self.top)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=10)
        
        # 左侧留空，右侧放关闭按钮
        spacer = ttk.Frame(bottom_frame)
        spacer.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        ttk.Button(bottom_frame, text="关闭", command=self.top.destroy, width=15).pack(side=tk.RIGHT, padx=5)
        
    def refresh_list(self):
        """刷新配置列表"""
        self.config_listbox.delete(0, tk.END)
        provider_names = {
            "openai": "OpenAI",
            "claude": "Claude",
            "deepseek": "DeepSeek",
            "doubao": "豆包",
            "qwen": "通义千问",
            "gemini": "Gemini"
        }
        
        for config in self.saved_configs:
            name = config.get("name", "")
            provider = config.get("provider", "")
            display_name = provider_names.get(provider, provider)
            enabled = "✓" if config.get("enabled") else "✗"
            text = f"{name} ({display_name}) {enabled}"
            self.config_listbox.insert(tk.END, text)
            
    def select_provider(self, provider):
        """选择提供商"""
        self.entry_provider.delete(0, tk.END)
        self.entry_provider.insert(0, provider)
        
    def on_select_config(self, event):
        """选择配置"""
        selection = self.config_listbox.curselection()
        if selection:
            idx = selection[0]
            config = self.saved_configs[idx]
            
            self.entry_provider.delete(0, tk.END)
            self.entry_provider.insert(0, config.get("provider", ""))
            
            self.entry_key.delete(0, tk.END)
            self.entry_key.insert(0, config.get("api_key", ""))
            
            self.entry_api_url.delete(0, tk.END)
            self.entry_api_url.insert(0, config.get("api_url", ""))
            
            self.entry_name.delete(0, tk.END)
            self.entry_name.insert(0, config.get("name", ""))
            
            self.var_enabled.set(config.get("enabled", True))
            
    def add_new_config(self):
        """保存新配置"""
        provider = self.entry_provider.get().strip()
        api_key = self.entry_key.get().strip()
        name = self.entry_name.get().strip() or provider
        
        if not provider or not api_key:
            self.lbl_test.config(text="请填写提供商和API密钥", foreground="red")
            return
            
        # 检查是否已存在
        for i, config in enumerate(self.saved_configs):
            if config.get("provider") == provider:
                # 更新
                self.saved_configs[i] = {
                    "provider": provider,
                    "api_key": api_key,
                    "api_url": self.entry_api_url.get().strip(),
                    "name": name,
                    "enabled": self.var_enabled.get()
                }
                break
        else:
            # 新增
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
        """使用选中的配置"""
        selection = self.config_listbox.curselection()
        if not selection:
            self.lbl_test.config(text="请先选择一个配置", foreground="red")
            return
            
        idx = selection[0]
        config = self.saved_configs[idx]
        
        # 保存当前使用的配置到 llm_config.json
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
        """删除选中的配置"""
        selection = self.config_listbox.curselection()
        if not selection:
            return
            
        idx = selection[0]
        del self.saved_configs[idx]
        self.save_all_configs()
        self.refresh_list()
        self.lbl_test.config(text="已删除", foreground="gray")
        
    def test_api(self):
        """测试API连接"""
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


class SecurityGUIv2:
    """安全测试可视化界面 v2"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI安全扫描工具 v2")
        self.root.geometry("950x780")
        
        self.create_widgets()
        
    def create_widgets(self):
        """创建界面"""
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title = ttk.Label(main_frame, text="AI安全扫描工具 v2", font=("微软雅黑", 18, "bold"))
        title.pack(pady=10)
        
        # 扫描目标
        scan_frame = ttk.LabelFrame(main_frame, text="扫描目标", padding="15")
        scan_frame.pack(fill=tk.X, pady=5)
        
        url_frame = ttk.Frame(scan_frame)
        url_frame.pack(fill=tk.X)
        
        ttk.Label(url_frame, text="URL地址:").pack(side=tk.LEFT)
        self.entry_url = ttk.Entry(url_frame, width=55, font=("微软雅黑", 11))
        self.entry_url.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.entry_url.insert(0, "https://")
        
        # 扫描选项
        opt_frame = ttk.LabelFrame(main_frame, text="扫描选项", padding="10")
        opt_frame.pack(fill=tk.X, pady=5)
        
        opt_row1 = ttk.Frame(opt_frame)
        opt_row1.pack(fill=tk.X)
        
        self.var_ssl = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row1, text="SSL/TLS", variable=self.var_ssl).pack(side=tk.LEFT, padx=10)
        
        self.var_headers = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row1, text="安全头", variable=self.var_headers).pack(side=tk.LEFT, padx=10)
        
        self.var_fingerprint = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row1, text="Web指纹", variable=self.var_fingerprint).pack(side=tk.LEFT, padx=10)
        
        self.var_directory = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row1, text="目录扫描", variable=self.var_directory).pack(side=tk.LEFT, padx=10)
        
        opt_row2 = ttk.Frame(opt_frame)
        opt_row2.pack(fill=tk.X, pady=5)
        
        self.var_sql = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="SQL注入", variable=self.var_sql).pack(side=tk.LEFT, padx=10)
        
        self.var_xss = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="XSS", variable=self.var_xss).pack(side=tk.LEFT, padx=10)
        
        self.var_ssrf = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="SSRF", variable=self.var_ssrf).pack(side=tk.LEFT, padx=10)
        
        self.var_command = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row2, text="命令注入", variable=self.var_command).pack(side=tk.LEFT, padx=10)
        
        self.var_sensitive = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="敏感信息", variable=self.var_sensitive).pack(side=tk.LEFT, padx=10)
        
        self.var_ai = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="AI分析", variable=self.var_ai).pack(side=tk.LEFT, padx=10)
        
        # 扫描按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.btn_scan = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan,
                                   style="Action.TButton")
        self.btn_scan.pack(side=tk.LEFT, padx=5, ipadx=15)
        
        self.btn_stop = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan,
                                   state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="快速扫描", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        
        self.btn_report = ttk.Button(btn_frame, text="查看报告", command=self.view_report, state=tk.DISABLED)
        self.btn_report.pack(side=tk.LEFT, padx=5)
        
        # LLM配置按钮
        self.btn_llm = ttk.Button(btn_frame, text="LLM配置", command=self.open_llm_config)
        self.btn_llm.pack(side=tk.RIGHT, padx=5)
        
        # LLM状态
        self.llm_status_var = tk.StringVar(value="LLM: 未配置")
        self.lbl_llm = ttk.Label(btn_frame, textvariable=self.llm_status_var, foreground="gray")
        self.lbl_llm.pack(side=tk.RIGHT, padx=10)
        
        self.check_llm_status()
        
        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # 结果统计
        stats_frame = ttk.LabelFrame(main_frame, text="扫描统计", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.lbl_total = ttk.Label(stats_frame, text="总问题: 0", font=("微软雅黑", 11))
        self.lbl_total.pack(side=tk.LEFT, padx=20)
        
        self.lbl_critical = ttk.Label(stats_frame, text="严重: 0", foreground="#ff6b6b", font=("微软雅黑", 11, "bold"))
        self.lbl_critical.pack(side=tk.LEFT, padx=20)
        
        self.lbl_high = ttk.Label(stats_frame, text="高危: 0", foreground="#ffa502", font=("微软雅黑", 11, "bold"))
        self.lbl_high.pack(side=tk.LEFT, padx=20)
        
        self.lbl_medium = ttk.Label(stats_frame, text="中危: 0", foreground="#ffd93d", font=("微软雅黑", 11, "bold"))
        self.lbl_medium.pack(side=tk.LEFT, padx=20)
        
        self.lbl_risk = ttk.Label(stats_frame, text="风险: -", foreground="#4cc9f0", font=("微软雅黑", 11, "bold"))
        self.lbl_risk.pack(side=tk.RIGHT, padx=20)
        
        # 结果显示
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=16, font=("Consolas", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X)
        
        # 存储结果
        self.scan_results = None
        self.report_path = None
        
    def log(self, message):
        """显示日志"""
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)
        
    def set_status(self, message):
        """设置状态"""
        self.status_var.set(message)
        self.root.update()
        
    def get_options(self):
        """获取扫描选项"""
        return {
            "ssl": self.var_ssl.get(),
            "security_headers": self.var_headers.get(),
            "fingerprint": self.var_fingerprint.get(),
            "directory_scan": self.var_directory.get(),
            "sql_injection": self.var_sql.get(),
            "xss": self.var_xss.get(),
            "ssrf": self.var_ssrf.get(),
            "command_injection": self.var_command.get(),
            "sensitive_data": self.var_sensitive.get(),
            "ai_analysis": self.var_ai.get()
        }
        
    def start_scan(self):
        """开始扫描"""
        url = self.entry_url.get().strip()
        
        if not url:
            messagebox.showwarning("警告", "请输入URL地址")
            return
            
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("警告", "URL必须以http://或https://开头")
            return
        
        self.scanner = None  # 保存scanner引用用于停止
        self.is_scanning = True  # 扫描状态标志
        
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress.start(10)
        self.set_status("正在扫描...")
        self.result_text.delete("1.0", tk.END)
        
        def scan_thread():
            try:
                scanner = EnhancedSecurityScanner()
                options = self.get_options()
                result = scanner.scan(url, options)
                
                # LLM深度分析
                llm_analyzer = self.get_llm_analyzer()
                if llm_analyzer and result.get("findings"):
                    self.root.after(0, lambda: self.set_status("正在进行LLM深度分析..."))
                    try:
                        llm_result = llm_analyzer.analyze_vulnerabilities(
                            result["findings"], 
                            url
                        )
                        if "analysis" in llm_result:
                            result["llm_analysis"] = llm_result["analysis"]
                            self.log("\n[LLM深度分析完成]")
                    except Exception as e:
                        self.log(f"\n[LLM分析失败: {e}]")
                
                self.scan_results = result
                self.report_path = scanner.generate_html_report()
                
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
        """停止扫描"""
        self.is_scanning = False
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.progress.stop()
        self.set_status("扫描已停止")
        self.log("\n扫描已停止")
        
    def update_results(self):
        """更新结果"""
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_report.config(state=tk.NORMAL)
        
        if not self.scan_results:
            return
            
        result = self.scan_results
        counts = result.get("severity_counts", {})
        
        self.lbl_total.config(text=f"总问题: {result.get('total_findings', 0)}")
        self.lbl_critical.config(text=f"严重: {counts.get('critical', 0)}")
        self.lbl_high.config(text=f"高危: {counts.get('high', 0)}")
        self.lbl_medium.config(text=f"中危: {counts.get('medium', 0)}")
        
        # AI分析
        if result.get("ai_analysis"):
            ai = result["ai_analysis"]
            risk = ai.get("risk_level", "-")
            self.lbl_risk.config(text=f"风险: {risk}")
        
        self.log(f"\n{'='*55}")
        self.log(f"扫描完成: {result['url']}")
        self.log(f"{'='*55}")
        
        # AI分析
        if result.get("ai_analysis"):
            ai = result["ai_analysis"]
            self.log(f"\n[AI智能分析]")
            self.log(f"  风险等级: {ai.get('risk_level', '')}")
            self.log(f"  {ai.get('summary', '')}")
            self.log(f"\n[修复建议]")
            for rec in ai.get("recommendations", []):
                self.log(f"  - {rec}")
            
        # LLM深度分析
        if result.get("llm_analysis"):
            self.log(f"\n{'='*55}")
            self.log(f"[LLM 深度分析]")
            self.log(f"{'='*55}")
            llm_text = result["llm_analysis"]
            # 分行显示
            for line in llm_text.split('\n')[:30]:  # 限制行数
                if line.strip():
                    self.log(f"  {line}")
            
        # 问题列表
        self.log(f"\n[详细发现]")
        for f in result.get("findings", []):
            severity = f.get("severity", "info").upper()
            self.log(f"[{severity}] {f.get('title', '')}")
            self.log(f"     {f.get('description', '')[:70]}")
            
        self.set_status(f"扫描完成 - 发现 {result.get('total_findings', 0)} 个问题")
        
    def quick_scan(self):
        """快速扫描"""
        self.entry_url.delete(0, tk.END)
        self.entry_url.insert(0, "https://httpbin.org")
        self.start_scan()
        
    def view_report(self):
        """查看报告"""
        if self.report_path:
            webbrowser.open(self.report_path)
            
    def open_llm_config(self):
        """打开LLM配置对话框"""
        dialog = LLMConfigDialog(self.root)
        self.check_llm_status()
        
    def check_llm_status(self):
        """检查LLM配置状态"""
        config_file = Path("llm_config.json")
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                if config.get("enabled") and config.get("api_key"):
                    provider = config.get("provider", "openai")
                    # 显示实际配置的大模型名称
                    provider_names = {
                        "openai": "OpenAI",
                        "claude": "Claude",
                        "azure": "Azure OpenAI",
                        "gemini": "Gemini",
                        "qwen": "通义千问",
                        "ernie": "文心一言",
                        "moonshot": "Moonshot",
                        "deepseek": "DeepSeek",
                        "doubao-seed-2.0-code": "豆包"
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
        """获取LLM分析器"""
        config_file = Path("llm_config.json")
        if not config_file.exists():
            return None
            
        try:
            with open(config_file) as f:
                config = json.load(f)
            if config.get("enabled") and config.get("api_key"):
                return LLMAnalyzer(provider=config.get("provider", "openai"), 
                                   api_key=config.get("api_key"))
        except:
            pass
        return None
        
    def run(self):
        """运行"""
        self.root.mainloop()


if __name__ == "__main__":
    app = SecurityGUIv2()
    app.run()
