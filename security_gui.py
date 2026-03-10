"""
安全测试GUI界面
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import webbrowser
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from security_scan import SecurityScanner


class SecurityGUI:
    """安全测试可视化界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI安全扫描工具")
        self.root.geometry("900x700")
        
        self.create_widgets()
        
    def create_widgets(self):
        """创建界面"""
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title = ttk.Label(main_frame, text="AI安全扫描工具", font=("微软雅黑", 18, "bold"))
        title.pack(pady=15)
        
        # 扫描目标
        scan_frame = ttk.LabelFrame(main_frame, text="扫描目标", padding="15")
        scan_frame.pack(fill=tk.X, pady=10)
        
        url_frame = ttk.Frame(scan_frame)
        url_frame.pack(fill=tk.X)
        
        ttk.Label(url_frame, text="URL地址:").pack(side=tk.LEFT)
        self.entry_url = ttk.Entry(url_frame, width=50, font=("微软雅黑", 11))
        self.entry_url.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.entry_url.insert(0, "https://")
        
        # 扫描选项
        opt_frame = ttk.Frame(scan_frame)
        opt_frame.pack(fill=tk.X, pady=10)
        
        self.var_sql = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="SQL注入", variable=self.var_sql).pack(side=tk.LEFT, padx=10)
        
        self.var_xss = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="XSS", variable=self.var_xss).pack(side=tk.LEFT, padx=10)
        
        self.var_headers = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="安全头", variable=self.var_headers).pack(side=tk.LEFT, padx=10)
        
        self.var_sensitive = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="敏感信息", variable=self.var_sensitive).pack(side=tk.LEFT, padx=10)
        
        self.var_ai = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="AI分析", variable=self.var_ai).pack(side=tk.LEFT, padx=10)
        
        # 扫描按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.btn_scan = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan,
                                   style="Action.TButton")
        self.btn_scan.pack(side=tk.LEFT, padx=5, ipadx=20)
        
        ttk.Button(btn_frame, text="快速扫描(演示)", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        
        self.btn_report = ttk.Button(btn_frame, text="查看报告", command=self.view_report, state=tk.DISABLED)
        self.btn_report.pack(side=tk.LEFT, padx=5)
        
        # 扫描进度
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # 结果显示
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # 结果统计
        stats_frame = ttk.Frame(result_frame)
        stats_frame.pack(fill=tk.X)
        
        self.lbl_total = ttk.Label(stats_frame, text="总问题: 0", font=("微软雅黑", 11))
        self.lbl_total.pack(side=tk.LEFT, padx=15)
        
        self.lbl_critical = ttk.Label(stats_frame, text="严重: 0", foreground="red", font=("微软雅黑", 11))
        self.lbl_critical.pack(side=tk.LEFT, padx=15)
        
        self.lbl_high = ttk.Label(stats_frame, text="高危: 0", foreground="orange", font=("微软雅黑", 11))
        self.lbl_high.pack(side=tk.LEFT, padx=15)
        
        self.lbl_medium = ttk.Label(stats_frame, text="中危: 0", foreground="#FFC107", font=("微软雅黑", 11))
        self.lbl_medium.pack(side=tk.LEFT, padx=15)
        
        # 结果文本
        self.result_text = scrolledtext.ScrolledText(result_frame, height=18, font=("Consolas", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
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
        
    def start_scan(self):
        """开始扫描"""
        url = self.entry_url.get().strip()
        
        if not url:
            messagebox.showwarning("警告", "请输入URL地址")
            return
            
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("警告", "URL必须以http://或https://开头")
            return
            
        self.btn_scan.config(state=tk.DISABLED)
        self.progress.start()
        self.set_status("正在扫描...")
        self.result_text.delete("1.0", tk.END)
        
        def scan_thread():
            try:
                scanner = SecurityScanner()
                result = scanner.scan_url(url, ai_analysis=self.var_ai.get())
                self.scan_results = result
                self.report_path = scanner.generate_report()
                
                # 更新界面
                self.root.after(0, self.update_results)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", str(e)))
                self.root.after(0, lambda: self.btn_scan.config(state=tk.NORMAL))
                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.set_status("扫描失败"))
                
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def update_results(self):
        """更新结果"""
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_report.config(state=tk.NORMAL)
        
        if not self.scan_results:
            return
            
        result = self.scan_results
        counts = result.get("severity_counts", {})
        
        self.lbl_total.config(text=f"总问题: {result.get('total_findings', 0)}")
        self.lbl_critical.config(text=f"严重: {counts.get('critical', 0)}")
        self.lbl_high.config(text=f"高危: {counts.get('high', 0)}")
        self.lbl_medium.config(text=f"中危: {counts.get('medium', 0)}")
        
        self.log(f"\n{'='*50}")
        self.log(f"扫描完成: {result['url']}")
        self.log(f"{'='*50}")
        
        # 显示AI分析
        if result.get("ai_analysis"):
            ai = result["ai_analysis"]
            self.log(f"\n[AI风险分析]")
            self.log(f"风险等级: {ai.get('risk_level', '')}")
            self.log(f"分析摘要: {ai.get('summary', '')}")
            self.log(f"\n[AI建议]")
            self.log(ai.get('overall_recommendation', ''))
            
        # 显示问题列表
        self.log(f"\n[详细发现]")
        for f in result.get("findings", []):
            severity = f.get("severity", "info")
            self.log(f"[{severity.upper()}] {f.get('title', '')}")
            self.log(f"    {f.get('description', '')[:80]}")
            
        self.set_status(f"扫描完成 - 发现 {result.get('total_findings', 0)} 个问题")
        
    def quick_scan(self):
        """快速扫描演示"""
        self.entry_url.delete(0, tk.END)
        self.entry_url.insert(0, "https://httpbin.org")
        self.start_scan()
        
    def view_report(self):
        """查看报告"""
        if self.report_path:
            webbrowser.open(self.report_path)
            
    def run(self):
        """运行"""
        self.root.mainloop()


if __name__ == "__main__":
    app = SecurityGUI()
    app.run()
