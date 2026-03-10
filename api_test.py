"""
API接口监控与自动化测试框架
功能：监控、自动化测试、压力测试、报告生成
"""

import json
import time
import random
import threading
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests


class APIMonitor:
    """API接口监控"""
    
    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self.endpoints = []
        self.results = []
        self.monitoring = False
        
    def add_endpoint(self, name: str, url: str, method: str = "GET", 
                     expected_status: int = 200, headers: dict = None):
        """添加监控端点"""
        self.endpoints.append({
            "name": name,
            "url": url,
            "method": method,
            "expected_status": expected_status,
            "headers": headers or {}
        })
        
    def check_endpoint(self, endpoint: Dict) -> Dict:
        """检查单个端点"""
        start_time = time.time()
        result = {
            "name": endpoint["name"],
            "url": endpoint["url"],
            "method": endpoint["method"],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            response = requests.request(
                method=endpoint["method"],
                url=endpoint["url"],
                headers=endpoint["headers"],
                timeout=10
            )
            
            result["status_code"] = response.status_code
            result["response_time"] = (time.time() - start_time) * 1000
            result["success"] = response.status_code == endpoint["expected_status"]
            result["error"] = None
            
        except Exception as e:
            result["status_code"] = 0
            result["response_time"] = (time.time() - start_time) * 1000
            result["success"] = False
            result["error"] = str(e)
            
        return result
    
    def check_all(self) -> List[Dict]:
        """检查所有端点"""
        results = []
        for endpoint in self.endpoints:
            result = self.check_endpoint(endpoint)
            results.append(result)
        self.results.extend(results)
        return results
    
    def start_monitoring(self, duration: int = 0):
        """开始监控"""
        self.monitoring = True
        print(f"开始监控 {len(self.endpoints)} 个端点...")
        
        while self.monitoring:
            results = self.check_all()
            
            # 打印结果
            for r in results:
                status = "OK" if r["success"] else "FAIL"
                print(f"[{r['name']}] {r['response_time']:.0f}ms - {status}")
            
            if duration > 0:
                duration -= self.check_interval
                if duration <= 0:
                    break
            else:
                time.sleep(self.check_interval)
                
        self.monitoring = False
        print("监控结束")
        
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring = False
        
    def get_health_status(self) -> Dict:
        """获取健康状态"""
        if not self.results:
            return {"status": "unknown", "total": 0}
            
        total = len(self.results)
        success = sum(1 for r in self.results if r["success"])
        avg_time = statistics.mean([r["response_time"] for r in self.results])
        
        return {
            "status": "healthy" if success == total else "degraded",
            "total": total,
            "success": success,
            "failed": total - success,
            "avg_response_time": avg_time
        }


class APITester:
    """API自动化测试"""
    
    def __init__(self):
        self.test_cases = []
        self.results = []
        
    def add_test_case(self, name: str, url: str, method: str = "GET",
                      headers: dict = None, params: dict = None, 
                      json_data: dict = None, expected_status: int = 200,
                      validate_response: dict = None):
        """添加测试用例"""
        self.test_cases.append({
            "name": name,
            "url": url,
            "method": method,
            "headers": headers or {},
            "params": params or {},
            "json_data": json_data,
            "expected_status": expected_status,
            "validate_response": validate_response or {}
        })
        
    def run_test(self, test_case: Dict) -> Dict:
        """运行单个测试"""
        start_time = time.time()
        result = {
            "name": test_case["name"],
            "url": test_case["url"],
            "method": test_case["method"],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            response = requests.request(
                method=test_case["method"],
                url=test_case["url"],
                headers=test_case["headers"],
                params=test_case["params"],
                json=test_case["json_data"],
                timeout=30
            )
            
            result["status_code"] = response.status_code
            result["response_time"] = (time.time() - start_time) * 1000
            result["response"] = response.json() if response.headers.get("content-type", "").find("json") >= 0 else response.text
            
            # 验证状态码
            status_ok = response.status_code == test_case["expected_status"]
            
            # 验证响应内容
            validation_errors = []
            if test_case["validate_response"]:
                for key, expected in test_case["validate_response"].items():
                    actual = result["response"].get(key) if isinstance(result["response"], dict) else None
                    if actual != expected:
                        validation_errors.append(f"{key}: expected {expected}, got {actual}")
            
            result["success"] = status_ok and len(validation_errors) == 0
            result["validation_errors"] = validation_errors
            result["error"] = None
            
        except Exception as e:
            result["status_code"] = 0
            result["response_time"] = (time.time() - start_time) * 1000
            result["success"] = False
            result["error"] = str(e)
            result["validation_errors"] = []
            
        return result
    
    def run_all(self) -> List[Dict]:
        """运行所有测试"""
        self.results = []
        print(f"\n开始运行 {len(self.test_cases)} 个测试用例...\n")
        
        for tc in self.test_cases:
            result = self.run_test(tc)
            self.results.append(result)
            
            status = "PASS" if result["success"] else "FAIL"
            print(f"[{status}] {result['name']} - {result.get('response_time', 0):.0f}ms")
            
            if not result["success"]:
                print(f"     Error: {result.get('error', result.get('validation_errors', []))}")
                
        return self.results
    
    def get_summary(self) -> Dict:
        """获取测试摘要"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r["success"])
        failed = total - passed
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{(passed/total*100):.1f}%" if total > 0 else "0%",
            "avg_response_time": statistics.mean([r.get("response_time", 0) for r in self.results]) if total > 0 else 0
        }


class LoadTester:
    """压力测试"""
    
    def __init__(self):
        self.results = []
        
    def load_test(self, url: str, method: str = "GET", 
                  headers: dict = None, json_data: dict = None,
                  concurrent_users: int = 10, 
                  requests_per_user: int = 10,
                  delay: float = 0.1) -> Dict:
        """压力测试"""
        print(f"\n压力测试配置:")
        print(f"  URL: {url}")
        print(f"  并发用户: {concurrent_users}")
        print(f"  每用户请求数: {requests_per_user}")
        print(f"  总请求数: {concurrent_users * requests_per_user}")
        print(f"\n开始测试...\n")
        
        self.results = []
        start_time = time.time()
        
        def make_request(user_id: int) -> List[Dict]:
            results = []
            for i in range(requests_per_user):
                req_start = time.time()
                try:
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers or {},
                        json=json_data,
                        timeout=30
                    )
                    results.append({
                        "user": user_id,
                        "request": i + 1,
                        "status_code": response.status_code,
                        "response_time": (time.time() - req_start) * 1000,
                        "success": response.status_code < 400
                    })
                except Exception as e:
                    results.append({
                        "user": user_id,
                        "request": i + 1,
                        "status_code": 0,
                        "response_time": (time.time() - req_start) * 1000,
                        "success": False,
                        "error": str(e)
                    })
                    
                if delay > 0:
                    time.sleep(delay)
                    
            return results
        
        # 并发执行
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(make_request, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                self.results.extend(future.result())
                
        total_time = time.time() - start_time
        
        # 统计结果
        success = sum(1 for r in self.results if r["success"])
        failed = len(self.results) - success
        response_times = [r["response_time"] for r in self.results]
        
        summary = {
            "url": url,
            "total_requests": len(self.results),
            "success": success,
            "failed": failed,
            "success_rate": f"{(success/len(self.results)*100):.1f}%" if self.results else "0%",
            "total_time": total_time,
            "requests_per_second": len(self.results) / total_time if total_time > 0 else 0,
            "avg_response_time": statistics.mean(response_times) if response_times else 0,
            "min_response_time": min(response_times) if response_times else 0,
            "max_response_time": max(response_times) if response_times else 0,
            "p50_response_time": statistics.median(response_times) if response_times else 0,
            "p95_response_time": statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times) if response_times else 0,
            "p99_response_time": statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else max(response_times) if response_times else 0,
        }
        
        print(f"\n压力测试结果:")
        print(f"  总请求数: {summary['total_requests']}")
        print(f"  成功: {summary['success']}")
        print(f"  失败: {summary['failed']}")
        print(f"  成功率: {summary['success_rate']}")
        print(f"  QPS: {summary['requests_per_second']:.1f}")
        print(f"  平均响应: {summary['avg_response_time']:.0f}ms")
        print(f"  P99响应: {summary['p99_response_time']:.0f}ms")
        
        return summary


class APIReportGenerator:
    """测试报告生成"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_html_report(self, monitor_results: List[Dict] = None,
                             test_results: List[Dict] = None,
                             load_results: Dict = None) -> str:
        """生成HTML报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 计算统计数据
        stats = {}
        
        if monitor_results:
            m_total = len(monitor_results)
            m_success = sum(1 for r in monitor_results if r.get("success"))
            stats["monitor"] = {
                "total": m_total,
                "success": m_success,
                "failed": m_total - m_success,
                "avg_time": statistics.mean([r.get("response_time", 0) for r in monitor_results]) if m_total > 0 else 0
            }
            
        if test_results:
            t_total = len(test_results)
            t_passed = sum(1 for r in test_results if r.get("success"))
            stats["test"] = {
                "total": t_total,
                "passed": t_passed,
                "failed": t_total - t_passed,
                "pass_rate": f"{(t_passed/t_total*100):.1f}%" if t_total > 0 else "0%"
            }
            
        if load_results:
            stats["load"] = load_results
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>API测试报告 - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #333; margin-bottom: 20px; }}
        h2 {{ color: #555; margin: 20px 0 10px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }}
        .stat {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; }}
        .stat-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        .success {{ color: #28a745; }}
        .fail {{ color: #dc3545; }}
        .warning {{ color: #ffc107; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 14px; }}
        th {{ background: #007bff; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-fail {{ background: #f8d7da; color: #721c24; }}
        .footer {{ text-align: center; color: #999; margin-top: 20px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>API测试报告</h1>
        <p>生成时间: {timestamp}</p>
"""
        
        # 监控结果
        if stats.get("monitor"):
            m = stats["monitor"]
            html += f"""
        <div class="card">
            <h2>接口监控</h2>
            <div class="grid">
                <div class="stat"><div class="stat-value">{m['total']}</div><div class="stat-label">总检查数</div></div>
                <div class="stat"><div class="stat-value success">{m['success']}</div><div class="stat-label">成功</div></div>
                <div class="stat"><div class="stat-value fail">{m['failed']}</div><div class="stat-label">失败</div></div>
                <div class="stat"><div class="stat-value">{m['avg_time']:.0f}ms</div><div class="stat-label">平均响应</div></div>
            </div>
        </div>
"""
        
        # 测试结果
        if stats.get("test"):
            t = stats["test"]
            html += f"""
        <div class="card">
            <h2>自动化测试</h2>
            <div class="grid">
                <div class="stat"><div class="stat-value">{t['total']}</div><div class="stat-label">总用例数</div></div>
                <div class="stat"><div class="stat-value success">{t['passed']}</div><div class="stat-label">通过</div></div>
                <div class="stat"><div class="stat-value fail">{t['failed']}</div><div class="stat-label">失败</div></div>
                <div class="stat"><div class="stat-value">{t['pass_rate']}</div><div class="stat-label">通过率</div></div>
            </div>
        </div>
"""
        
        # 压力测试结果
        if stats.get("load"):
            l = stats["load"]
            html += f"""
        <div class="card">
            <h2>压力测试</h2>
            <div class="grid">
                <div class="stat"><div class="stat-value">{l['total_requests']}</div><div class="stat-label">总请求数</div></div>
                <div class="stat"><div class="stat-value success">{l['success_rate']}</div><div class="stat-label">成功率</div></div>
                <div class="stat"><div class="stat-value">{l['requests_per_second']:.1f}</div><div class="stat-label">QPS</div></div>
                <div class="stat"><div class="stat-value">{l['avg_response_time']:.0f}ms</div><div class="stat-label">平均响应</div></div>
            </div>
            <table>
                <tr><th>指标</th><th>值</th></tr>
                <tr><td>P50</td><td>{l['p50_response_time']:.0f}ms</td></tr>
                <tr><td>P95</td><td>{l['p95_response_time']:.0f}ms</td></tr>
                <tr><td>P99</td><td>{l['p99_response_time']:.0f}ms</td></tr>
                <tr><td>最大响应</td><td>{l['max_response_time']:.0f}ms</td></tr>
            </table>
        </div>
"""
        
        # 详细结果表
        if test_results:
            html += """
        <div class="card">
            <h2>测试详情</h2>
            <table>
                <tr><th>用例名称</th><th>URL</th><th>响应时间</th><th>状态码</th><th>结果</th></tr>
"""
            for r in test_results:
                status_class = "badge-success" if r.get("success") else "badge-fail"
                status_text = "PASS" if r.get("success") else "FAIL"
                html += f"""
                <tr>
                    <td>{r.get('name', '')}</td>
                    <td>{r.get('url', '')}</td>
                    <td>{r.get('response_time', 0):.0f}ms</td>
                    <td>{r.get('status_code', '')}</td>
                    <td><span class="badge {status_class}">{status_text}</span></td>
                </tr>
"""
            html += """
            </table>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>API测试框架 v1.0</p>
        </div>
    </div>
</body>
</html>"""
        
        # 保存报告
        report_file = self.output_dir / f"api_report_{timestamp}.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return str(report_file)


def demo():
    """演示"""
    print("=" * 50)
    print("API测试框架演示")
    print("=" * 50)
    
    # 1. 监控测试
    print("\n1. 接口监控测试")
    monitor = APIMonitor()
    monitor.add_endpoint("百度", "https://www.baidu.com", expected_status=200)
    monitor.add_endpoint("淘宝", "https://www.taobao.com", expected_status=200)
    monitor_results = monitor.check_all()
    for r in monitor_results:
        print(f"  {r['name']}: {r['response_time']:.0f}ms - {'OK' if r['success'] else 'FAIL'}")
    
    # 2. 自动化测试
    print("\n2. 自动化测试")
    tester = APITester()
    tester.add_test_case("获取IP", "https://httpbin.org/ip", expected_status=200)
    tester.add_test_case("GET请求", "https://httpbin.org/get", expected_status=200)
    tester.add_test_case("POST请求", "https://httpbin.org/post", method="POST", 
                         json_data={"test": "data"}, expected_status=200)
    tester.add_test_case("失败测试", "https://httpbin.org/status/500", expected_status=200)
    test_results = tester.run_all()
    summary = tester.get_summary()
    print(f"\n测试摘要: {summary}")
    
    # 3. 压力测试
    print("\n3. 压力测试")
    load_tester = LoadTester()
    load_results = load_tester.load_test(
        url="https://httpbin.org/get",
        concurrent_users=5,
        requests_per_user=5,
        delay=0.1
    )
    
    # 4. 生成报告
    print("\n4. 生成报告")
    reporter = APIReportGenerator()
    report_path = reporter.generate_html_report(
        monitor_results=monitor_results,
        test_results=test_results,
        load_results=load_results
    )
    print(f"报告: {report_path}")
    
    print("\n完成!")


if __name__ == "__main__":
    demo()
