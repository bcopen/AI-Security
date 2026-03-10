"""
API测试框架 - 可视化界面 (增强版)
支持：参数配置、测试数据上传、多接口管理
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import json
from datetime import datetime
from pathlib import Path

# 导入API测试模块
import sys
sys.path.insert(0, str(Path(__file__).parent))
from api_test import APITester, LoadTester, APIReportGenerator


class ParamDialog:
    """参数配置对话框"""
    
    def __init__(self, parent, api_data=None):
        self.result = None
        self.top = tk.Toplevel(parent)
        self.top.title("接口参数配置")
        self.top.geometry("600x500")
        self.top.transient(parent)
        self.top.grab_set()
        
        # 初始化数据
        self.params = api_data.get("params", {}) if api_data else {}
        self.headers = api_data.get("headers", {}) if api_data else {}
        self.json_data = api_data.get("json", {}) if api_data else {}
        self.validate = api_data.get("validate_response", {}) if api_data else {}
        
        self.create_widgets()
        
        if api_data:
            self.load_data()
            
        self.top.wait_window()
        
    def create_widgets(self):
        """创建组件"""
        # Notebook
        notebook = ttk.Notebook(self.top)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ===== Query参数 =====
        self.frame_query = ttk.Frame(notebook)
        notebook.add(self.frame_query, text="Query参数")
        
        ttk.Label(self.frame_query, text="参数格式: key=value, 每行一个").pack(pady=5)
        self.txt_query = scrolledtext.ScrolledText(self.frame_query, height=15)
        self.txt_query.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # ===== Header参数 =====
        self.frame_header = ttk.Frame(notebook)
        notebook.add(self.frame_header, text="Header参数")
        
        ttk.Label(self.frame_header, text="参数格式: key=value, 每行一个").pack(pady=5)
        self.txt_header = scrolledtext.ScrolledText(self.frame_header, height=15)
        self.txt_header.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # ===== Body参数 =====
        self.frame_body = ttk.Frame(notebook)
        notebook.add(self.frame_body, text="Body (JSON)")
        
        ttk.Label(self.frame_body, text="JSON格式请求体").pack(pady=5)
        self.txt_body = scrolledtext.ScrolledText(self.frame_body, height=15, font=("Consolas", 10))
        self.txt_body.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # ===== 响应验证 =====
        self.frame_validate = ttk.Frame(notebook)
        notebook.add(self.frame_validate, text="响应验证")
        
        ttk.Label(self.frame_validate, text="验证响应字段: field=expected_value, 每行一个").pack(pady=5)
        self.txt_validate = scrolledtext.ScrolledText(self.frame_validate, height=15)
        self.txt_validate.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 按钮
        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="确定", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.cancel).pack(side=tk.RIGHT)
        
    def load_data(self):
        """加载数据"""
        # Query
        for k, v in self.params.items():
            self.txt_query.insert(tk.END, f"{k}={v}\n")
            
        # Header
        for k, v in self.headers.items():
            self.txt_header.insert(tk.END, f"{k}={v}\n")
            
        # Body
        if self.json_data:
            self.txt_body.insert(tk.END, json.dumps(self.json_data, indent=2, ensure_ascii=False))
            
        # Validate
        for k, v in self.validate.items():
            self.txt_validate.insert(tk.END, f"{k}={v}\n")
            
    def parse_text(self, text):
        """解析文本为字典"""
        result = {}
        for line in text.strip().split("\n"):
            line = line.strip()
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
        return result
        
    def parse_json(self, text):
        """解析JSON"""
        try:
            return json.loads(text.strip()) if text.strip() else {}
        except:
            return {}
            
    def ok(self):
        """确定"""
        self.result = {
            "params": self.parse_text(self.txt_query.get("1.0", tk.END)),
            "headers": self.parse_text(self.txt_header.get("1.0", tk.END)),
            "json": self.parse_json(self.txt_body.get("1.0", tk.END)),
            "validate_response": self.parse_text(self.txt_validate.get("1.0", tk.END))
        }
        self.top.destroy()
        
    def cancel(self):
        """取消"""
        self.top.destroy()


class APITestGUI:
    """API测试可视化界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("API接口测试工具 (增强版)")
        self.root.geometry("1000x750")
        
        # 数据
        self.api_list = []
        self.test_results = []
        self.load_results = None
        
        # 创建界面
        self.create_widgets()
        
        # 加载配置
        self.load_config()
        
    def create_widgets(self):
        """创建组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 标题 =====
        title = ttk.Label(main_frame, text="API接口测试工具", font=("微软雅黑", 16, "bold"))
        title.pack(pady=10)
        
        # ===== 上方: API列表和添加 =====
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 左侧: 接口列表
        list_frame = ttk.LabelFrame(top_frame, text="API接口列表", padding="5")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # 表格
        columns = ("name", "url", "method", "params", "headers", "body")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        self.tree.heading("name", text="名称")
        self.tree.heading("url", text="URL")
        self.tree.heading("method", text="方法")
        self.tree.heading("params", text="参数")
        self.tree.heading("headers", text="Header")
        self.tree.heading("body", text="Body")
        
        self.tree.column("name", width=100)
        self.tree.column("url", width=300)
        self.tree.column("method", width=60)
        self.tree.column("params", width=60)
        self.tree.column("headers", width=60)
        self.tree.column("body", width=60)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.edit_api)
        
        # 右侧: 添加/编辑区
        add_frame = ttk.LabelFrame(top_frame, text="添加/编辑接口", padding="10")
        add_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        # 基本信息
        ttk.Label(add_frame, text="接口名称:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.entry_name = ttk.Entry(add_frame, width=25)
        self.entry_name.grid(row=0, column=1, pady=3)
        
        ttk.Label(add_frame, text="URL地址:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.entry_url = ttk.Entry(add_frame, width=25)
        self.entry_url.grid(row=1, column=1, pady=3)
        
        ttk.Label(add_frame, text="请求方法:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.combo_method = ttk.Combobox(add_frame, values=["GET", "POST", "PUT", "DELETE", "PATCH"], 
                                         width=23, state="readonly")
        self.combo_method.set("GET")
        self.combo_method.grid(row=2, column=1, pady=3)
        
        ttk.Label(add_frame, text="期望状态码:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.entry_expected = ttk.Entry(add_frame, width=25)
        self.entry_expected.insert(0, "200")
        self.entry_expected.grid(row=3, column=1, pady=3)
        
        # 参数配置按钮
        ttk.Label(add_frame, text="参数配置:").grid(row=4, column=0, sticky=tk.W, pady=3)
        self.btn_config_params = ttk.Button(add_frame, text="配置参数", 
                                             command=self.open_param_dialog)
        self.btn_config_params.grid(row=4, column=1, sticky=tk.W, pady=3)
        
        # 测试数据上传
        ttk.Label(add_frame, text="测试数据:").grid(row=5, column=0, sticky=tk.W, pady=3)
        self.file_path_var = tk.StringVar(value="未选择文件")
        ttk.Label(add_frame, textvariable=self.file_path_var, foreground="gray",
                  font=("微软雅黑", 8)).grid(row=5, column=1, sticky=tk.W)
        
        upload_frame = ttk.Frame(add_frame)
        upload_frame.grid(row=6, column=0, columnspan=2, pady=5)
        
        ttk.Button(upload_frame, text="上传JSON", command=self.upload_test_data).pack(side=tk.LEFT, padx=2)
        ttk.Button(upload_frame, text="上传CSV", command=self.upload_csv_data).pack(side=tk.LEFT, padx=2)
        
        # 操作按钮
        btn_frame = ttk.Frame(add_frame)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="添加接口", command=self.add_api).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="编辑接口", command=self.edit_selected_api).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="删除选中", command=self.delete_api).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="清空列表", command=self.clear_apis).pack(fill=tk.X, pady=2)
        
        # ===== 中间: 测试选项 =====
        option_frame = ttk.LabelFrame(main_frame, text="测试选项", padding="10")
        option_frame.pack(fill=tk.X, pady=5)
        
        opt_row = ttk.Frame(option_frame)
        opt_row.pack(fill=tk.X)
        
        ttk.Label(opt_row, text="并发数:").pack(side=tk.LEFT)
        self.spin_concurrent = ttk.Spinbox(opt_row, from_=1, to=200, width=10)
        self.spin_concurrent.set(10)
        self.spin_concurrent.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(opt_row, text="每用户请求:").pack(side=tk.LEFT)
        self.spin_requests = ttk.Spinbox(opt_row, from_=1, to=1000, width=10)
        self.spin_requests.set(10)
        self.spin_requests.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(opt_row, text="请求间隔(秒):").pack(side=tk.LEFT)
        self.spin_delay = ttk.Spinbox(opt_row, from_=0, to=10, width=10)
        self.spin_delay.set(0.1)
        self.spin_delay.pack(side=tk.LEFT, padx=5)
        
        # 按钮
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        self.btn_auto_test = ttk.Button(action_frame, text="自动化测试", 
                                        command=self.run_auto_test,
                                        style="Action.TButton")
        self.btn_auto_test.pack(side=tk.LEFT, padx=10, ipadx=20)
        
        self.btn_load_test = ttk.Button(action_frame, text="压力测试", 
                                        command=self.run_load_test,
                                        style="Action.TButton")
        self.btn_load_test.pack(side=tk.LEFT, padx=10, ipadx=20)
        
        self.btn_view_report = ttk.Button(action_frame, text="生成报告", 
                                         command=self.view_report)
        self.btn_view_report.pack(side=tk.LEFT, padx=10, ipadx=20)
        
        ttk.Button(action_frame, text="保存配置", command=self.save_config).pack(side=tk.RIGHT, padx=10)
        
        # ===== 下方: 结果显示 =====
        result_frame = ttk.LabelFrame(main_frame, text="测试结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=12, font=("Consolas", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=5)
        
        # 当前编辑的API数据
        self.current_api_params = {}
        self.test_data_file = None
        
    def add_api(self):
        """添加API"""
        name = self.entry_name.get().strip()
        url = self.entry_url.get().strip()
        method = self.combo_method.get()
        expected = self.entry_expected.get().strip() or "200"
        
        if not name or not url:
            messagebox.showwarning("警告", "请输入接口名称和URL")
            return
            
        api_data = {
            "name": name,
            "url": url,
            "method": method,
            "expected_status": int(expected),
            "params": self.current_api_params.get("params", {}),
            "headers": self.current_api_params.get("headers", {}),
            "json": self.current_api_params.get("json", {}),
            "validate_response": self.current_api_params.get("validate_response", {}),
            "test_data_file": self.test_data_file
        }
        
        self.api_list.append(api_data)
        
        # 添加到表格
        has_params = "✓" if api_data["params"] else ""
        has_headers = "✓" if api_data["headers"] else ""
        has_body = "✓" if api_data["json"] else ""
        
        self.tree.insert("", tk.END, values=(
            name, url, method, has_params, has_headers, has_body
        ))
        
        self.clear_inputs()
        self.log(f"已添加接口: {name}")
        
    def edit_selected_api(self):
        """编辑选中的接口"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要编辑的接口")
            return
            
        item = selected[0]
        idx = self.tree.index(item)
        
        if idx < len(self.api_list):
            api = self.api_list[idx]
            self.entry_name.delete(0, tk.END)
            self.entry_name.insert(0, api["name"])
            self.entry_url.delete(0, tk.END)
            self.entry_url.insert(0, api["url"])
            self.combo_method.set(api["method"])
            self.entry_expected.delete(0, tk.END)
            self.entry_expected.insert(0, str(api.get("expected_status", 200)))
            
            self.current_api_params = {
                "params": api.get("params", {}),
                "headers": api.get("headers", {}),
                "json": api.get("json", {}),
                "validate_response": api.get("validate_response", {})
            }
            
            self.test_data_file = api.get("test_data_file")
            if self.test_data_file:
                self.file_path_var.set(self.test_data_file.split("/")[-1])
            
    def edit_api(self, event):
        """双击编辑"""
        self.edit_selected_api()
        
    def delete_api(self):
        """删除选中"""
        selected = self.tree.selection()
        if selected:
            for item in selected:
                idx = self.tree.index(item)
                self.tree.delete(item)
                if idx < len(self.api_list):
                    self.api_list.pop(idx)
                    
    def clear_apis(self):
        """清空列表"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.api_list = []
        
    def clear_inputs(self):
        """清空输入"""
        self.entry_name.delete(0, tk.END)
        self.entry_url.delete(0, tk.END)
        self.combo_method.set("GET")
        self.entry_expected.delete(0, tk.END)
        self.entry_expected.insert(0, "200")
        self.current_api_params = {}
        self.test_data_file = None
        self.file_path_var.set("未选择文件")
        
    def open_param_dialog(self):
        """打开参数配置对话框"""
        dialog = ParamDialog(self.root, self.current_api_params)
        if dialog.result:
            self.current_api_params = dialog.result
            self.log("参数已配置")
            
    def upload_test_data(self):
        """上传测试数据(JSON)"""
        file_path = filedialog.askopenfilename(
            title="选择测试数据文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if file_path:
            self.test_data_file = file_path
            self.file_path_var.set(file_path.split("/")[-1])
            self.log(f"已选择测试数据: {file_path}")
            
    def upload_csv_data(self):
        """上传CSV测试数据"""
        file_path = filedialog.askopenfilename(
            title="选择CSV测试数据",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
        )
        
        if file_path:
            self.test_data_file = file_path
            self.file_path_var.set(file_path.split("/")[-1])
            self.log(f"已选择CSV数据: {file_path}")
            
    def log(self, message):
        """显示日志"""
        self.result_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.result_text.see(tk.END)
        
    def set_status(self, message):
        """设置状态"""
        self.status_var.set(message)
        self.root.update()
        
    def save_config(self):
        """保存配置"""
        config = {"test_cases": self.api_list}
        
        with open("api_config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            
        messagebox.showinfo("提示", "配置已保存到 api_config.json")
        
    def load_config(self):
        """加载配置"""
        try:
            with open("api_config.json", "r", encoding="utf-8") as f:
                config = json.load(f)
                
            for tc in config.get("test_cases", []):
                self.api_list.append(tc)
                
                has_params = "✓" if tc.get("params") else ""
                has_headers = "✓" if tc.get("headers") else ""
                has_body = "✓" if tc.get("json") else ""
                
                self.tree.insert("", tk.END, values=(
                    tc.get("name", ""),
                    tc.get("url", ""),
                    tc.get("method", "GET"),
                    has_params, has_headers, has_body
                ))
        except:
            pass
            
    def run_auto_test(self):
        """运行自动化测试"""
        if not self.api_list:
            messagebox.showwarning("警告", "请先添加API接口")
            return
            
        self.btn_auto_test.config(state=tk.DISABLED)
        self.set_status("正在运行自动化测试...")
        
        def test_thread():
            try:
                tester = APITester()
                
                for api in self.api_list:
                    # 加载测试数据文件
                    params = api.get("params", {})
                    headers = api.get("headers", {})
                    json_data = api.get("json", {})
                    
                    # 如果有测试数据文件，读取数据
                    if api.get("test_data_file"):
                        try:
                            with open(api["test_data_file"], "r", encoding="utf-8") as f:
                                test_data = json.load(f)
                                # 合并数据
                                if isinstance(test_data, dict):
                                    json_data.update(test_data)
                        except Exception as e:
                            self.log(f"读取测试数据失败: {e}")
                    
                    tester.add_test_case(
                        name=api["name"],
                        url=api["url"],
                        method=api.get("method", "GET"),
                        headers=headers,
                        params=params,
                        json_data=json_data if json_data else None,
                        expected_status=api.get("expected_status", 200),
                        validate_response=api.get("validate_response", {})
                    )
                
                self.log("=" * 50)
                self.log("开始自动化测试")
                self.log("=" * 50)
                
                results = tester.run_all()
                summary = tester.get_summary()
                
                self.test_results = results
                
                self.log("")
                self.log("测试完成!")
                self.log(f"总计: {summary['total']} | 通过: {summary['passed']} | 失败: {summary['failed']}")
                self.log(f"通过率: {summary['pass_rate']}")
                
                self.set_status("自动化测试完成")
                
            except Exception as e:
                self.log(f"错误: {str(e)}")
                self.set_status("测试失败")
            finally:
                self.root.after(0, lambda: self.btn_auto_test.config(state=tk.NORMAL))
                
        threading.Thread(target=test_thread, daemon=True).start()
        
    def run_load_test(self):
        """运行压力测试"""
        if not self.api_list:
            messagebox.showwarning("警告", "请先添加API接口")
            return
            
        self.btn_load_test.config(state=tk.DISABLED)
        
        concurrent = int(self.spin_concurrent.get())
        requests = int(self.spin_requests.get())
        delay = float(self.spin_delay.get())
        
        def test_thread():
            try:
                self.log("=" * 50)
                self.log("开始压力测试")
                self.log(f"并发: {concurrent} | 每用户请求: {requests}")
                self.log("=" * 50)
                
                tester = LoadTester()
                
                # 使用第一个API进行压力测试
                api = self.api_list[0]
                
                # 如果有测试数据文件
                json_data = api.get("json", {})
                if api.get("test_data_file"):
                    try:
                        with open(api["test_data_file"], "r", encoding="utf-8") as f:
                            json_data = json.load(f)
                    except:
                        pass
                
                self.load_results = tester.load_test(
                    url=api["url"],
                    method=api.get("method", "GET"),
                    headers=api.get("headers", {}),
                    json_data=json_data if json_data else None,
                    concurrent_users=concurrent,
                    requests_per_user=requests,
                    delay=delay
                )
                
                self.log("")
                self.log("压力测试完成!")
                self.log(f"成功率: {self.load_results['success_rate']}")
                self.log(f"QPS: {self.load_results['requests_per_second']:.1f}")
                self.log(f"平均响应: {self.load_results['avg_response_time']:.0f}ms")
                self.log(f"P99响应: {self.load_results['p99_response_time']:.0f}ms")
                
                self.set_status("压力测试完成")
                
            except Exception as e:
                self.log(f"错误: {str(e)}")
                self.set_status("测试失败")
            finally:
                self.root.after(0, lambda: self.btn_load_test.config(state=tk.NORMAL))
                
        threading.Thread(target=test_thread, daemon=True).start()
        
    def view_report(self):
        """查看报告"""
        try:
            reporter = APIReportGenerator()
            
            test_results = self.test_results if self.test_results else []
            
            if not test_results and self.api_list:
                tester = APITester()
                for api in self.api_list:
                    tester.add_test_case(
                        name=api["name"],
                        url=api["url"],
                        method=api.get("method", "GET"),
                        expected_status=api.get("expected_status", 200)
                    )
                test_results = tester.run_all()
            
            report_path = reporter.generate_html_report(
                test_results=test_results,
                load_results=self.load_results
            )
            
            import webbrowser
            webbrowser.open(report_path)
            
            self.log(f"报告已生成: {report_path}")
            
        except Exception as e:
            messagebox.showerror("错误", f"生成报告失败: {str(e)}")
            
    def run(self):
        """运行"""
        self.root.mainloop()


def main():
    app = APITestGUI()
    app.run()


if __name__ == "__main__":
    main()
