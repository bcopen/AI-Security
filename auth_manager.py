"""
认证管理器 - 支持多种认证方式
"""

import json
import time
import requests
from typing import Dict, Optional
from pathlib import Path
from urllib.parse import urlparse


class AuthManager:
    """认证管理器"""
    
    def __init__(self, config_file: str = "auth_config.json"):
        self.config_file = Path(config_file)
        self.session = requests.Session()
        self.auth_config = {}
        self.load_config()
        
    def load_config(self):
        """加载认证配置"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.auth_config = json.load(f)
            except:
                self.auth_config = {}
                
    def save_config(self):
        """保存认证配置"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.auth_config, f, indent=2, ensure_ascii=False)
            
    def set_auth(self, auth_type: str, config: dict):
        """设置认证配置"""
        self.auth_config = {
            "type": auth_type,
            "config": config,
            "timestamp": time.time()
        }
        self.save_config()
        
    def login(self, base_url: str) -> bool:
        """执行登录"""
        if not self.auth_config:
            return False
            
        auth_type = self.auth_config.get("type")
        config = self.auth_config.get("config", {})
        
        try:
            if auth_type == "cookie":
                return self._login_cookie(base_url, config)
            elif auth_type == "token":
                return self._login_token(base_url, config)
            elif auth_type == "basic":
                return self._login_basic(base_url, config)
            elif auth_type == "oauth2":
                return self._login_oauth2(base_url, config)
            else:
                return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
            
    def _login_cookie(self, base_url: str, config: dict) -> bool:
        """Cookie认证"""
        login_url = config.get("login_url", base_url + "/login")
        username = config.get("username", "")
        password = config.get("password", "")
        cookie_name = config.get("cookie_name", "session")
        
        # 准备登录数据
        data = config.get("data", {})
        if username and password:
            username_field = config.get("username_field", "username")
            password_field = config.get("password_field", "password")
            data[username_field] = username
            data[password_field] = password
            
        # 额外的请求头
        headers = config.get("headers", {})
        
        try:
            response = self.session.post(login_url, data=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # 检查是否设置了Cookie
                cookies = self.session.cookies.get_dict()
                if cookie_name in cookies:
                    return True
                    
                # 检查响应中是否包含token
                try:
                    resp_json = response.json()
                    if "token" in resp_json:
                        self.session.headers["Authorization"] = f"Bearer {resp_json['token']}"
                        return True
                except:
                    pass
                    
            return False
        except:
            return False
            
    def _login_token(self, base_url: str, config: dict) -> bool:
        """Bearer Token认证"""
        token_url = config.get("token_url", base_url + "/api/token")
        username = config.get("username", "")
        password = config.get("password", "")
        
        try:
            # 获取token
            data = {
                "username": username,
                "password": password,
                "grant_type": config.get("grant_type", "password")
            }
            
            # 添加额外的认证字段
            extra_fields = config.get("extra_fields", {})
            data.update(extra_fields)
            
            headers = config.get("headers", {})
            
            response = self.session.post(token_url, data=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                resp_json = response.json()
                
                # 尝试多种token字段名
                token = (resp_json.get("access_token") or 
                        resp_json.get("token") or 
                        resp_json.get("id_token"))
                
                if token:
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    
                    # 存储refresh_token
                    refresh_token = resp_json.get("refresh_token")
                    if refresh_token:
                        self.auth_config["_refresh_token"] = refresh_token
                        
                    return True
                    
            return False
        except:
            return False
            
    def _login_basic(self, base_url: str, config: dict) -> bool:
        """Basic认证"""
        username = config.get("username", "")
        password = config.get("password", "")
        
        if username and password:
            self.session.auth = (username, password)
            return True
        return False
        
    def _login_oauth2(self, base_url: str, config: dict) -> bool:
        """OAuth2认证"""
        token_url = config.get("token_url")
        client_id = config.get("client_id", "")
        client_secret = config.get("client_secret", "")
        scope = config.get("scope", "")
        auth_url = config.get("auth_url")
        
        # 方式1: 客户端凭证模式
        if config.get("grant_type") == "client_credentials":
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope
            }
            
        # 方式2: 密码模式
        elif config.get("grant_type") == "password":
            data = {
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": config.get("username", ""),
                "password": config.get("password", ""),
                "scope": scope
            }
            
        # 方式3: 授权码模式（需要code）
        elif config.get("grant_type") == "authorization_code":
            code = config.get("code", "")
            redirect_uri = config.get("redirect_uri", "")
            
            data = {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri
            }
        else:
            return False
            
        try:
            headers = config.get("headers", {})
            response = self.session.post(token_url, data=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                resp_json = response.json()
                token = (resp_json.get("access_token") or 
                        resp_json.get("token"))
                        
                if token:
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    return True
                    
            return False
        except:
            return False
            
    def refresh_token(self) -> bool:
        """刷新Token"""
        if not self.auth_config.get("_refresh_token"):
            return False
            
        auth_type = self.auth_config.get("type")
        if auth_type != "token":
            return False
            
        config = self.auth_config.get("config", {})
        token_url = config.get("token_url")
        
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.auth_config["_refresh_token"],
            "client_id": config.get("client_id", ""),
            "client_secret": config.get("client_secret", "")
        }
        
        try:
            response = self.session.post(token_url, data=data, timeout=10)
            if response.status_code == 200:
                resp_json = response.json()
                token = resp_json.get("access_token")
                if token:
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    return True
        except:
            pass
            
        return False
        
    def get_session(self) -> requests.Session:
        """获取已认证的Session"""
        return self.session
        
    def logout(self):
        """登出"""
        self.session = requests.Session()
        self.auth_config = {}
        self.save_config()
        
    def is_authenticated(self) -> bool:
        """检查是否已认证"""
        return "Authorization" in self.session.headers or len(self.session.cookies) > 0


def quick_auth(url: str, auth_type: str = "none", **kwargs) -> requests.Session:
    """快速认证"""
    manager = AuthManager()
    
    if auth_type == "none":
        return manager.get_session()
        
    manager.set_auth(auth_type, kwargs)
    
    if manager.login(url):
        return manager.get_session()
    else:
        raise Exception("Authentication failed")


if __name__ == "__main__":
    # 测试
    manager = AuthManager()
    
    # 设置Cookie认证
    manager.set_auth("cookie", {
        "login_url": "https://example.com/login",
        "username": "test",
        "password": "test123",
        "username_field": "email",
        "password_field": "pwd"
    })
    
    print("Auth config saved")
    print(manager.auth_config)
