"""
API测试框架 - 命令行入口
"""

import argparse
import json
import sys
from pathlib import Path

from api_test import APIMonitor, APITester, LoadTester, APIReportGenerator


def cmd_monitor(args):
    """监控命令"""
    monitor = APIMonitor(check_interval=args.interval)
    
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
            for ep in config.get("endpoints", []):
                monitor.add_endpoint(
                    name=ep["name"],
                    url=ep["url"],
                    method=ep.get("method", "GET"),
                    expected_status=ep.get("expected_status", 200),
                    headers=ep.get("headers", {})
                )
    
    if args.endpoints:
        for ep in args.endpoints:
            name, url = ep.split(":", 1)
            monitor.add_endpoint(name, url)
    
    if args.duration:
        monitor.start_monitoring(args.duration)
    else:
        results = monitor.check_all()
        for r in results:
            print(f"{r['name']}: {r['response_time']:.0f}ms - {'OK' if r['success'] else 'FAIL'}")
            
    return monitor.results


def cmd_test(args):
    """测试命令"""
    tester = APITester()
    
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
            for tc in config.get("test_cases", []):
                tester.add_test_case(
                    name=tc["name"],
                    url=tc["url"],
                    method=tc.get("method", "GET"),
                    headers=tc.get("headers", {}),
                    params=tc.get("params", {}),
                    json_data=tc.get("json"),
                    expected_status=tc.get("expected_status", 200),
                    validate_response=tc.get("validate_response", {})
                )
    else:
        # 添加示例测试
        tester.add_test_case("健康检查", args.url or "https://httpbin.org/get", expected_status=200)
    
    results = tester.run_all()
    summary = tester.get_summary()
    print(f"\n测试摘要: {summary}")
    
    return results, summary


def cmd_load(args):
    """压力测试命令"""
    tester = LoadTester()
    results = tester.load_test(
        url=args.url,
        method=args.method,
        headers=json.loads(args.headers) if args.headers else None,
        json_data=json.loads(args.json) if args.json else None,
        concurrent_users=args.users,
        requests_per_user=args.requests,
        delay=args.delay
    )
    return results


def cmd_report(args):
    """报告命令"""
    reporter = APIReportGenerator()
    
    monitor_results = None
    test_results = None
    load_results = None
    
    if args.monitor:
        with open(args.monitor) as f:
            monitor_results = json.load(f)
            
    if args.test:
        with open(args.test) as f:
            test_results = json.load(f)
            
    if args.load:
        with open(args.load) as f:
            load_results = json.load(f)
    
    report_path = reporter.generate_html_report(
        monitor_results=monitor_results,
        test_results=test_results,
        load_results=load_results
    )
    print(f"报告: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="API测试框架")
    subparsers = parser.add_subparsers(dest="command", help="命令")
    
    # 监控命令
    monitor_parser = subparsers.add_parser("monitor", help="接口监控")
    monitor_parser.add_argument("-e", "--endpoints", nargs="+", help="端点列表 (name:url)")
    monitor_parser.add_argument("-c", "--config", help="配置文件")
    monitor_parser.add_argument("-d", "--duration", type=int, help="监控时长(秒)")
    monitor_parser.add_argument("-i", "--interval", type=int, default=60, help="检查间隔")
    
    # 测试命令
    test_parser = subparsers.add_parser("test", help="自动化测试")
    test_parser.add_argument("-u", "--url", help="测试URL")
    test_parser.add_argument("-c", "--config", help="配置文件")
    
    # 压力测试命令
    load_parser = subparsers.add_parser("load", help="压力测试")
    load_parser.add_argument("url", help="测试URL")
    load_parser.add_argument("-m", "--method", default="GET", help="请求方法")
    load_parser.add_argument("-H", "--headers", help="请求头JSON")
    load_parser.add_argument("-j", "--json", help="请求体JSON")
    load_parser.add_argument("-u", "--users", type=int, default=10, help="并发数")
    load_parser.add_argument("-r", "--requests", type=int, default=10, help="每用户请求数")
    load_parser.add_argument("-d", "--delay", type=float, default=0.1, help="请求间隔")
    
    # 报告命令
    report_parser = subparsers.add_parser("report", help="生成报告")
    report_parser.add_argument("-m", "--monitor", help="监控结果文件")
    report_parser.add_argument("-t", "--test", help="测试结果文件")
    report_parser.add_argument("-l", "--load", help="压力测试结果文件")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "load":
        cmd_load(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
