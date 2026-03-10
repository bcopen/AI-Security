"""
LLM AI分析器 - 集成ChatGPT/Claude进行深度分析
"""

import json
import requests
from typing import Dict, List, Optional


class LLMAnalyzer:
    """LLM AI分析器"""
    
    def __init__(self, provider: str = "openai", api_key: str = "", api_url: str = ""):
        """
        初始化LLM分析器
        
        Args:
            provider: "openai", "claude", "qwen", "deepseek", "doubao", "gemini"
            api_key: API密钥
            api_url: 自定义API地址(可选)
        """
        self.provider = provider
        self.api_key = api_key
        self.api_url = api_url
        
    def analyze_vulnerabilities(self, findings: List[Dict], 
                                target_url: str = "",
                                context: str = "") -> Dict:
        """
        使用LLM分析漏洞
        
        Args:
            findings: 漏洞列表
            target_url: 目标URL
            context: 额外上下文
        """
        if not self.api_key:
            return {"error": "需要配置API密钥", "using_fallback": True}
            
        # 构建提示词
        prompt = self._build_prompt(findings, target_url, context)
        
        try:
            if self.provider == "openai":
                return self._call_openai(prompt)
            elif self.provider == "claude":
                return self._call_claude(prompt)
            elif self.provider == "qwen":
                return self._call_qwen(prompt)
            elif self.provider == "deepseek":
                return self._call_deepseek(prompt)
            elif self.provider == "doubao":
                return self._call_doubao(prompt)
            elif self.provider == "gemini":
                return self._call_gemini(prompt)
            else:
                # 默认尝试openai
                return self._call_openai(prompt)
        except Exception as e:
            return {"error": str(e), "using_fallback": True}
            
    def _build_prompt(self, findings: List[Dict], target_url: str, context: str) -> str:
        """构建分析提示词"""
        
        findings_text = "\n".join([
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', '')}"
            for f in findings
        ])
        
        prompt = f"""你是一位资深网络安全专家和渗透测试工程师。请分析以下安全扫描结果，提供专业的安全评估和修复建议。

## 目标信息
- URL: {target_url}
- 额外上下文: {context}

## 扫描发现
{findings_text}

## 请提供以下分析:

### 1. 风险评估
- 总体风险等级 (严重/高/中/低)
- 风险说明

### 2. 漏洞分析
- 每个严重和高危漏洞的技术分析
- 漏洞的潜在影响

### 3. 修复建议
- 针对每个漏洞的具体修复步骤
- 优先级排序

### 4. 额外建议
- 安全架构改进建议
- 长期安全策略

请用中文回复，格式化为清晰的报告。"""
        
        return prompt
        
    def _call_openai(self, prompt: str) -> Dict:
        """调用OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "你是一位专业的网络安全专家。"},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return {
                "analysis": result["choices"][0]["message"]["content"],
                "model": "gpt-3.5-turbo",
                "using_fallback": False
            }
        else:
            return {"error": f"API错误: {response.status_code}"}
            
    def _call_claude(self, prompt: str) -> Dict:
        """调用Claude API"""
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 2000,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return {
                "analysis": result["content"][0]["text"],
                "model": "claude-3-haiku",
                "using_fallback": False
            }
        else:
            return {"error": f"API错误: {response.status_code}"}
            
    def _call_qwen(self, prompt: str) -> Dict:
        """调用通义千问 API"""
        # 检查是否有自定义API地址
        api_url = getattr(self, 'api_url', None) or "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "qwen-turbo",
            "input": {"prompt": prompt},
            "parameters": {"max_tokens": 2000, "temperature": 0.7}
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result.get("output", {}).get("text", ""),
                    "model": "qwen-turbo",
                    "using_fallback": False
                }
            else:
                return {"error": f"API错误: {response.status_code} - {response.text[:100]}"}
        except Exception as e:
            return {"error": f"调用失败: {str(e)}"}
            
    def _call_deepseek(self, prompt: str) -> Dict:
        """调用 DeepSeek API"""
        api_url = getattr(self, 'api_url', None) or "https://api.deepseek.com/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.7
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result["choices"][0]["message"]["content"],
                    "model": "deepseek-chat",
                    "using_fallback": False
                }
            else:
                return {"error": f"API错误: {response.status_code}"}
        except Exception as e:
            return {"error": f"调用失败: {str(e)}"}
            
    def _call_doubao(self, prompt: str) -> Dict:
        """调用豆包 API (字节跳动)"""
        api_url = getattr(self, 'api_url', None) or "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "doubao-seed-2.0-code",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result["choices"][0]["message"]["content"],
                    "model": "doubao-seed-2.0-code",
                    "using_fallback": False
                }
            else:
                return {"error": f"API错误: {response.status_code}"}
        except Exception as e:
            return {"error": f"调用失败: {str(e)}"}
            
    def _call_gemini(self, prompt: str) -> Dict:
        """调用 Google Gemini API"""
        api_url = getattr(self, 'api_url', None) or f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.api_key}"
        
        headers = {"Content-Type": "application/json"}
        
        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 2000, "temperature": 0.7}
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return {
                    "analysis": result["candidates"][0]["content"]["parts"][0]["text"],
                    "model": "gemini-pro",
                    "using_fallback": False
                }
            else:
                return {"error": f"API错误: {response.status_code}"}
        except Exception as e:
            return {"error": f"调用失败: {str(e)}"}
            
    def generate_exploit_scenario(self, finding: Dict, target_url: str) -> Dict:
        """生成漏洞利用场景"""
        
        prompt = f"""作为渗透测试专家，请描述如何利用以下漏洞:

漏洞: {finding.get('title', '')}
类型: {finding.get('category', '')}
严重性: {finding.get('severity', '')}
描述: {finding.get('description', '')}
目标: {target_url}

请描述:
1. 攻击原理
2. 利用步骤
3. 潜在影响
4. 防御方法

用中文回复。"""
        
        if not self.api_key:
            return {"error": "需要API密钥"}
            
        try:
            if self.provider == "openai":
                return self._call_openai(prompt)
            else:
                return self._call_claude(prompt)
        except Exception as e:
            return {"error": str(e)}
            
    def compare_with_owasp(self, findings: List[Dict]) -> Dict:
        """与OWASP Top 10对比分析"""
        
        prompt = f"""作为安全专家，请将这些发现与OWASP Top 10 2021进行对比:

{json.dumps(findings, indent=2, ensure_ascii=False)}

请分析:
1. 这些漏洞属于OWASP哪些类别
2. 与最新OWASP趋势的关系
3. 应该在OWASP清单中优先关注哪些

用中文回复。"""
        
        if not self.api_key:
            return {"error": "需要API密钥"}
            
        try:
            if self.provider == "openai":
                return self._call_openai(prompt)
        except Exception as e:
            return {"error": str(e)}


def demo():
    """演示 - 使用模拟分析（无API密钥时）"""
    
    print("=" * 60)
    print("LLM AI分析器演示")
    print("=" * 60)
    
    # 示例漏洞数据
    findings = [
        {
            "severity": "high",
            "category": "Injection",
            "title": "SQL注入漏洞",
            "description": "参数id存在SQL注入"
        },
        {
            "severity": "medium", 
            "category": "Security Headers",
            "title": "缺少安全响应头",
            "description": "缺少X-Frame-Options"
        },
        {
            "severity": "high",
            "category": "Sensitive Data",
            "title": "API密钥泄露",
            "description": "代码中发现硬编码的API密钥"
        }
    ]
    
    print("\n示例漏洞:")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['title']}")
    
    print("\n" + "=" * 60)
    print("如需使用真实LLM分析，请配置API密钥:")
    print("=" * 60)
    print("""
# 方式1: 设置环境变量
import os
os.environ["OPENAI_API_KEY"] = "your-key"

# 方式2: 直接传入
analyzer = LLMAnalyzer(provider="openai", api_key="your-key")

# 使用
result = analyzer.analyze_vulnerabilities(findings, "https://example.com")
print(result["analysis"])
""")
    
    # 模拟分析结果（无API时）
    print("\n" + "=" * 60)
    print("模拟AI分析结果（基于规则）:")
    print("=" * 60)
    print("""
### 1. 风险评估
- 总体风险: 高
- 发现2个高危漏洞，1个中危漏洞

### 2. 漏洞分析
- SQL注入: 可导致数据泄露或数据库控制
- API密钥泄露: 可能导致第三方服务被滥用

### 3. 修复建议 (优先级)
1. [紧急] 修复SQL注入 - 使用参数化查询
2. [高] 移除硬编码的API密钥 - 使用密钥管理服务
3. [中] 添加安全响应头 - 配置X-Frame-Options

### 4. 额外建议
- 实施安全代码审查流程
- 定期进行渗透测试
- 建立安全开发生命周期(SDL)
""")


if __name__ == "__main__":
    demo()
