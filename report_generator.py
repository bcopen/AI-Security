"""
报告生成模块
支持 HTML, JSON, PDF 格式
支持历史趋势图表
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from fpdf import FPDF


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.history_file = self.reports_dir / "scan_history.json"
        
    def save_scan_history(self, result: dict):
        """保存扫描历史"""
        history = self.load_history()
        
        scan_record = {
            "id": len(history) + 1,
            "url": result.get("url"),
            "timestamp": result.get("timestamp"),
            "total_findings": result.get("total_findings", 0),
            "severity_counts": result.get("severity_counts", {}),
            "risk_level": result.get("ai_analysis", {}).get("risk_level", "未知"),
            "cvss_score": result.get("ai_analysis", {}).get("cvss_score", 0.0)
        }
        
        history.append(scan_record)
        
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
            
        return scan_record
        
    def load_history(self) -> List[dict]:
        """加载扫描历史"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []
        
    def generate_json_report(self, result: dict) -> str:
        """生成JSON格式报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report_data = {
            "report_info": {
                "version": "3.0",
                "generated_at": timestamp,
                "scanner": "AI Security Scanner"
            },
            "scan_result": result
        }
        
        report_file = self.reports_dir / f"security_report_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        self.save_scan_history(result)
        
        return str(report_file)
        
    def generate_pdf_report(self, result: dict) -> str:
        """生成PDF格式报告 - 支持中文"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        pdf = FPDF(unit='mm', format='A4')
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # 尝试添加中文字体
        chinese_font = 'helvetica'
        try:
            font_path = Path('simsun.ttc')
            if font_path.exists():
                # 添加常规和粗体字体
                pdf.add_font('SimSun', '', str(font_path))
                pdf.add_font('SimSun', 'B', str(font_path))
                chinese_font = 'SimSun'
        except Exception as e:
            print(f"Font load error: {e}")
            chinese_font = 'helvetica'
        
        # 标题 - 使用常规字体然后设置大小来模拟粗体
        pdf.set_font(chinese_font, '', 18)
        pdf.cell(0, 12, '[AI Security Scan Report]', ln=True, align='C')
        
        pdf.set_font(chinese_font, '', 9)
        pdf.cell(0, 8, f'Date: {timestamp}', ln=True, align='C')
        pdf.ln(5)
        
        # 扫描概要
        pdf.set_font(chinese_font, '', 14)
        pdf.cell(0, 10, '[Scan Summary]', ln=True)
        pdf.set_font(chinese_font, '', 11)
        
        url = result.get('url', '')
        pdf.cell(0, 7, f'Target URL: {url}', ln=True)
        pdf.cell(0, 7, f'Total Issues: {result.get("total_findings", 0)}', ln=True)
        
        # 严重程度统计
        counts = result.get('severity_counts', {})
        severity_styles = [
            ('critical', (255, 0, 0), 'CRITICAL', 'SEVERE'),
            ('high', (255, 165, 0), 'HIGH', 'HIGH'),
            ('medium', (255, 215, 0), 'MEDIUM', 'MEDIUM'),
            ('low', (0, 200, 0), 'LOW', 'LOW')
        ]
        
        for sev, color, en_label, cn_label in severity_styles:
            count = counts.get(sev, 0)
            pdf.set_text_color(*color)
            pdf.set_font(chinese_font, 'B', 11)
            pdf.cell(0, 7, f'[{cn_label}] {count}', ln=True)
            
        pdf.set_text_color(0, 0, 0)
        
        # AI分析
        ai = result.get('ai_analysis', {})
        if ai:
            pdf.ln(3)
            pdf.set_font(chinese_font, '', 14)
            pdf.cell(0, 10, '[AI Analysis]', ln=True)
            pdf.set_font(chinese_font, '', 11)
            risk = ai.get('risk_level', 'Unknown')
            pdf.cell(0, 7, f'Risk Level: {risk}', ln=True)
            pdf.cell(0, 7, f'CVSS Score: {ai.get("cvss_score", 0.0)}', ln=True)
            
        # 发现的问题
        pdf.ln(3)
        pdf.set_font(chinese_font, '', 14)
        pdf.cell(0, 10, '[Findings]', ln=True)
        pdf.set_font(chinese_font, '', 9)
        
        for i, f in enumerate(result.get('findings', [])[:30], 1):
            sev = f.get('severity', 'info')
            color = {'critical': (255, 0, 0), 'high': (255, 165, 0), 'medium': (255, 215, 0), 'low': (0, 200, 0)}.get(sev, (100, 100, 100))
            pdf.set_text_color(*color)
            pdf.set_font(chinese_font, 'B', 9)
            title = f.get('title', '')
            pdf.cell(0, 6, f'{i}. [{sev.upper()}] {title}', ln=True)
            pdf.set_text_color(100, 100, 100)
            pdf.set_font(chinese_font, '', 8)
            desc = f.get('description', '')[:80]
            pdf.cell(0, 5, f'    -> {desc}', ln=True)
            
        pdf.set_text_color(0, 0, 0)
        
        report_file = self.reports_dir / f"security_report_{timestamp}.pdf"
        pdf.output(str(report_file))
        
        self.save_scan_history(result)
        
        return str(report_file)
        
    def _safe_text(self, text: str) -> str:
        """将文本转换为PDF安全格式(ASCII兼容)"""
        if not text:
            return ""
        # 移除或替换非ASCII字符
        safe = []
        for char in str(text):
            if ord(char) < 128:
                safe.append(char)
            else:
                safe.append('?')
        return ''.join(safe)
        
    def generate_html_report(self, result: dict) -> str:
        """生成HTML格式报告"""
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
        
        .stats {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ background: #0f3460; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ff6b6b; }}
        .high {{ color: #ffa502; }}
        .medium {{ color: #ffd93d; }}
        .low {{ color: #6bcb77; }}
        .info {{ color: #4d96ff; }}
        
        .ai-analysis {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 25px; border-radius: 12px; margin: 20px 0; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-size: 18px; font-weight: bold; }}
        
        .finding {{ background: #0f3460; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid; }}
        .finding.critical {{ border-color: #ff6b6b; }}
        .finding.high {{ border-color: #ffa502; }}
        .finding.medium {{ border-color: #ffd93d; }}
        .finding.low {{ border-color: #6bcb77; }}
        
        .footer {{ text-align: center; color: #666; margin-top: 30px; padding-top: 20px; border-top: 1px solid #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AI安全扫描报告</h1>
        <p class="header-info">扫描时间: {timestamp} | 扫描器: AI Security Scanner v3.0</p>
"""
        
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
            html += f"""
        <div class="ai-analysis">
            <h2>AI智能分析</h2>
            <p><span class="risk-badge">{ai.get('risk_level', '低')}风险</span></p>
            <p style="margin: 15px 0;">{ai.get('summary', '')}</p>
        </div>
"""
        
        html += """
        <h2>详细发现</h2>
"""
        for f in result.get("findings", []):
            severity = f.get("severity", "info")
            html += f"""
        <div class="finding {severity}">
            <strong>{f.get('title', '')}</strong> [{severity.upper()}]
            <p style="color:#aaa;margin:5px 0;">{f.get('description', '')}</p>
            <p style="color:#6bcb77;font-size:13px;">{f.get('recommendation', '')}</p>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>AI Security Scanner v3.0 | 扫描完成</p>
        </div>
    </div>
</body>
</html>"""
        
        report_file = self.reports_dir / f"security_report_{timestamp}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        self.save_scan_history(result)
        
        return str(report_file)
        
    def generate_trend_chart(self, days: int = 30) -> str:
        """生成趋势图表"""
        history = self.load_history()
        
        if not history:
            return None
            
        timestamps = []
        totals = []
        criticals = []
        highs = []
        mediums = []
        
        for record in history[-days:]:
            ts = record.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(ts)
                timestamps.append(dt.strftime('%m-%d'))
            except:
                timestamps.append(ts[:10] if len(ts) > 10 else ts)
                
            totals.append(record.get('total_findings', 0))
            criticals.append(record.get('severity_counts', {}).get('critical', 0))
            highs.append(record.get('severity_counts', {}).get('high', 0))
            mediums.append(record.get('severity_counts', {}).get('medium', 0))
            
        if not timestamps:
            return None
            
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        fig.suptitle('Security Scan History Trend', fontsize=16, fontweight='bold')
        
        ax1.plot(timestamps, totals, marker='o', linewidth=2, label='Total Issues', color='#4d96ff')
        ax1.fill_between(timestamps, totals, alpha=0.3, color='#4d96ff')
        ax1.set_ylabel('Total Issues')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_title('Total Issues Over Time')
        
        ax2.bar(timestamps, criticals, label='Critical', color='#ff6b6b', alpha=0.8)
        ax2.bar(timestamps, highs, bottom=criticals, label='High', color='#ffa502', alpha=0.8)
        ax2.bar(timestamps, mediums, bottom=[c+h for c,h in zip(criticals, highs)], label='Medium', color='#ffd93d', alpha=0.8)
        ax2.set_xlabel('Scan Date')
        ax2.set_ylabel('Issues Count')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        ax2.set_title('Vulnerability Severity Distribution')
        
        # 中文标签
        ax1.set_ylabel('问题数')
        ax1.legend(labels=['问题总数'])
        ax1.set_title('问题数量趋势')
        
        ax2.set_xlabel('扫描日期')
        ax2.set_ylabel('问题数')
        ax2.legend(labels=['严重', '高危', '中危'])
        ax2.set_title('漏洞严重程度分布')
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        chart_file = self.reports_dir / f"trend_chart_{datetime.now().strftime('%Y%m%d')}.png"
        plt.savefig(chart_file, dpi=150, facecolor='#16213e')
        plt.close()
        
        return str(chart_file)
        
    def generate_risk_distribution_chart(self) -> str:
        """生成风险分布饼图"""
        history = self.load_history()
        
        if not history:
            return None
            
        risk_counts = {"严重": 0, "高": 0, "中": 0, "低": 0, "极低": 0}
        
        for record in history:
            risk = record.get('risk_level', '低')
            if risk in risk_counts:
                risk_counts[risk] += 1
            elif risk == "未知":
                risk_counts["低"] += 1
                
        labels = [k for k, v in risk_counts.items() if v > 0]
        sizes = [v for v in risk_counts.values() if v > 0]
        
        if not labels:
            return None
            
        colors = ['#ff6b6b', '#ffa502', '#ffd93d', '#6bcb77', '#4d96ff']
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                           colors=colors[:len(labels)], startangle=90)
        
        for text in texts:
            text.set_color('white')
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_weight('bold')
            
        ax.set_title('Risk Level Distribution / Risk Level', fontsize=14, fontweight='bold')
        
        chart_file = self.reports_dir / f"risk_distribution_{datetime.now().strftime('%Y%m%d')}.png"
        plt.savefig(chart_file, dpi=150, facecolor='#16213e')
        plt.close()
        
        return str(chart_file)
        
    def generate_trend_html(self, days: int = 30) -> str:
        """生成趋势HTML页面"""
        history = self.load_history()
        
        trend_chart = self.generate_trend_chart(days)
        risk_chart = self.generate_risk_distribution_chart()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>安全扫描历史趋势</title>
    <style>
        body { font-family: 'Microsoft YaHei', 'Segoe UI', Arial; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #fff; text-align: center; }
        h2 { color: #4cc9f0; margin: 20px 0 10px; }
        .chart-container { background: #16213e; padding: 20px; border-radius: 12px; margin: 20px 0; }
        .chart-container img { max-width: 100%; border-radius: 8px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
        .stat { background: #0f3460; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #4cc9f0; }
        tr:hover { background: #0f3460; }
    </style>
</head>
<body>
    <div class="container">
        <h1>安全扫描历史趋势</h1>
"""
        
        total_scans = len(history)
        total_issues = sum(h.get('total_findings', 0) for h in history)
        avg_issues = total_issues / total_scans if total_scans > 0 else 0
        
        html += f"""
        <div class="stats">
            <div class="stat"><div class="stat-value">{total_scans}</div><div>扫描次数</div></div>
            <div class="stat"><div class="stat-value">{total_issues}</div><div>问题总数</div></div>
            <div class="stat"><div class="stat-value">{avg_issues:.1f}</div><div>平均问题</div></div>
            <div class="stat"><div class="stat-value">{days}</div><div>天数</div></div>
        </div>
"""
        
        if trend_chart:
            html += f"""
        <div class="chart-container">
            <h2>问题趋势图</h2>
            <img src="{Path(trend_chart).name}" alt="趋势图">
        </div>
"""
        
        if risk_chart:
            html += f"""
        <div class="chart-container">
            <h2>风险分布图</h2>
            <img src="{Path(risk_chart).name}" alt="风险分布">
        </div>
"""
        
        html += """
        <h2>最近扫描记录</h2>
        <table>
            <tr><th>编号</th><th>扫描地址</th><th>日期</th><th>问题数</th><th>风险等级</th></tr>
"""
        
        for record in history[-20:]:
            ts = record.get('timestamp', '')[:10]
            html += f"""
            <tr>
                <td>{record.get('id', '')}</td>
                <td>{record.get('url', '')[:50]}</td>
                <td>{ts}</td>
                <td>{record.get('total_findings', 0)}</td>
                <td>{record.get('risk_level', '')}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>"""
        
        report_file = self.reports_dir / f"trends_{timestamp}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return str(report_file)
        
    def get_statistics(self) -> dict:
        """获取统计信息"""
        history = self.load_history()
        
        if not history:
            return {}
            
        total_scans = len(history)
        total_issues = sum(h.get('total_findings', 0) for h in history)
        
        severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for h in history:
            for sev in severity_totals:
                severity_totals[sev] += h.get('severity_counts', {}).get(sev, 0)
                
        return {
            "total_scans": total_scans,
            "total_issues": total_issues,
            "avg_issues": total_issues / total_scans if total_scans > 0 else 0,
            "severity_totals": severity_totals
        }


def generate_all_reports(result: dict, reports_dir: str = "reports") -> dict:
    """生成所有格式的报告"""
    generator = ReportGenerator(reports_dir)
    
    reports = {"html": "", "json": "", "pdf": ""}
    
    try:
        reports["html"] = generator.generate_html_report(result)
    except Exception as e:
        print(f"HTML report error: {e}")
        
    try:
        reports["json"] = generator.generate_json_report(result)
    except Exception as e:
        print(f"JSON report error: {e}")
        
    try:
        reports["pdf"] = generator.generate_pdf_report(result)
    except Exception as e:
        print(f"PDF report error: {e}")
    
    return reports


if __name__ == "__main__":
    generator = ReportGenerator()
    
    print("=== Report Generator Test ===")
    print(f"Reports directory: {generator.reports_dir}")
    
    history = generator.load_history()
    print(f"Total scan history: {len(history)}")
    
    stats = generator.get_statistics()
    print(f"Statistics: {stats}")
    
    trend_html = generator.generate_trend_html(30)
    print(f"Trend report: {trend_html}")
