#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""云南财经大学校园网静默登录脚本"""

import requests
import json
import sys
import urllib3
import re
import socket
import hashlib
import time
import random
import hmac
import math
import uuid
import os
from typing import Optional, Dict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#出生校园网连https都没有，要我关验证提示

'''
关于校园网加密的实现⬇️
'''

def ordat(msg: str, idx: int) -> int:
    return ord(msg[idx]) if len(msg) > idx else 0


def sencode(msg: str, key: bool) -> list:
    """将字符串编码为整数数组"""
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg: list, key: bool) -> str:
    """将整数数组解码为字符串"""
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return ""
        ll = m
    result = []
    for i in range(0, l):
        result.append(chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff))
    s = "".join(result)
    if key:
        return s[0:ll]
    return s


def get_xencode(msg: str, key: str) -> str:
    """XOR加密 js的同款逻辑"""
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def get_base64(s: str) -> str:
    """自定义Base64编码 自研加密这一块"""
    _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    if not s:
        return s
    
    def _getbyte(s: str, i: int) -> int:
        x = ord(s[i])
        if x > 255:
            raise ValueError("INVALID_CHARACTER_ERR: DOM Exception 5")
        return x
    
    x = []
    imax = len(s) - len(s) % 3
    
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + 
                 _ALPHA[((b10 >> 6) & 63)] + _ALPHA[(b10 & 63)])
    
    if len(s) - imax == 1:
        b10 = _getbyte(s, imax) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + "==")
    elif len(s) - imax == 2:
        b10 = (_getbyte(s, imax) << 16) | (_getbyte(s, imax + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + "=")
    
    return "".join(x)


class CampusNetworkLogin:
    """校园网登录类 我给写死了，如果将来登录界面变了就改一下"""
    
    def __init__(self, service_ip: str = "http://172.16.130.31", ac_id: int = 7):
        self.service_ip = service_ip.rstrip('/')
        self.ac_id = ac_id
        self.session = requests.Session()
        self.session.timeout = 10
        self.session.verify = False
    
    def get_local_ip(self) -> str:
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return ""
    
    def get_mac_address(self) -> str:
        """获取MAC地址"""
        try:
            mac = uuid.getnode()
            return ':'.join(['{:02x}'.format((mac >> i) & 0xff) for i in range(0, 48, 8)][::-1])
        except:
            return ""
    
    def get_login_info(self) -> Dict:
        """获取登录所需的信息"""
        try:
            response = self.session.get(f"{self.service_ip}/srun_portal_pc", 
                                      params={'ac_id': self.ac_id, 'theme': 'ynufe'})
            config = {}
            config_match = re.search(r'var\s+CONFIG\s*=\s*({.*?});', response.text, re.DOTALL)
            if config_match:
                try:
                    config = json.loads(config_match.group(1).replace("'", '"'))
                except:
                    pass
        except:
            config = {}
        
        return {
            'ip': config.get('ip', self.get_local_ip()),
            'mac': config.get('mac', self.get_mac_address()),
            'nas': config.get('nas', ''),
            'url': config.get('url', ''),
            'config': config
        }
    
    def _get_callback_id(self) -> str:
        """生成回调ID"""
        return f"jQuery{random.randint(100000000000000000000, 999999999999999999999)}_{int(time.time() * 1000)}"
    
    def _parse_jsonp(self, text: str) -> Optional[Dict]:
        """解析JSONP响应"""
        if text.startswith('jQuery') and '(' in text and ')' in text:
            try:
                json_str = text[text.find('(') + 1:text.rfind(')')]
                return json.loads(json_str)
            except:
                pass
        return None
    
    def get_challenge(self, username: str, ip: str = '') -> Optional[str]:
        """获取challenge值"""
        try:
            params = {
                'callback': self._get_callback_id(),
                'username': username,
                '_': str(int(time.time() * 1000)),
            }
            if ip:
                params['ip'] = ip
            
            response = self.session.get(f"{self.service_ip}/cgi-bin/get_challenge", params=params,
                                      headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                              'Referer': f"{self.service_ip}/srun_portal_pc?ac_id={self.ac_id}&theme=ynufe",
                                              'Accept': 'text/javascript, application/javascript, */*; q=0.01'})
            
            if response.status_code == 200:
                data = self._parse_jsonp(response.text.strip())
                if data and data.get('challenge'):
                    return data['challenge']
            return None
        except Exception as e:
            print(f"获取challenge异常: {e}")
            return None
    
    def _encode_user_info(self, username: str, password: str, ip: str, challenge: str) -> str:
        """加密用户信息"""
        try:
            info_dict = {"username": username, "password": password, "ip": ip,
                        "acid": str(self.ac_id), "enc_ver": "srun_bx1"}
            info_json = json.dumps(info_dict, separators=(',', ':'))
            return "{SRBX1}" + get_base64(get_xencode(info_json, challenge))
        except Exception as e:
            print(f"加密用户信息失败: {e}")
            return ''
    
    def _get_chksum(self, username: str, hmd5: str, ip: str, challenge: str, info: str, n: str = '200', type_: str = '1') -> str:
        """计算chksum参数 校验码这一块"""
        try:
            s = f"{challenge}{username}{challenge}{hmd5}{challenge}{self.ac_id}{challenge}{ip}{challenge}{n}{challenge}{type_}{challenge}{info}"
            return hashlib.sha1(s.encode('utf-8')).hexdigest()
        except:
            return ''
    
    def login(self, username: str, password: str, domain: str = "1- @ynufe") -> Dict:
        """执行登录"""
        try:
            login_info = self.get_login_info()
            ip = login_info.get('ip', '')
            
            # 获得真正用户名 咱们校园网用户名是 用户名@权限组
            domain_part = (domain.split('@')[-1] if '@' in domain else domain.split(' @')[-1] if ' @' in domain else domain).strip()
            full_username = f"{username}@{domain_part}"
            
            # 经典challenge
            challenge = self.get_challenge(full_username)
            if not challenge:
                return {'success': False, 'message': '获取challenge失败'}
            
            # 计算加密参数
            hmd5 = hmac.new(challenge.encode(), password.encode(), hashlib.md5).hexdigest()
            info = self._encode_user_info(full_username, password, ip, challenge)
            if not info:
                return {'success': False, 'message': '加密用户信息失败'}
            
            chksum = self._get_chksum(full_username, hmd5, ip, challenge, info)
            timestamp = int(time.time() * 1000)
            
            # 登录请求
            params = {
                'callback': self._get_callback_id(),
                'action': 'login',
                'username': full_username,
                'password': '{MD5}' + hmd5,
                'os': 'Windows 10',
                'name': 'Windows',
                'double_stack': '0',
                'chksum': chksum,
                'info': info,
                'ac_id': str(self.ac_id),
                'ip': ip,
                'n': '200',
                'type': '1',
                '_': str(timestamp),
            }
            
            response = self.session.get(f"{self.service_ip}/cgi-bin/srun_portal", params=params,
                                       headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                               'Referer': f"{self.service_ip}/srun_portal_pc?ac_id={self.ac_id}&theme=ynufe",
                                               'Accept': 'text/javascript, application/javascript, */*; q=0.01'})
            
            if response.status_code == 200:
                result = self._parse_response(response)
                return result if result else {'success': False, 'message': f'无法解析响应: {response.text[:500]}'}
            return {'success': False, 'message': f'HTTP {response.status_code}: {response.text[:500]}'}
        except Exception as e:
            return {'success': False, 'message': f'登录失败: {str(e)}'}
    
    def _check_success(self, data: Dict) -> bool:
        """检查登录是否成功"""
        error = data.get('error', '')
        return (error == 'ok' or data.get('res') == 'ok' or 
                data.get('suc_msg') == 'login_ok' or data.get('ecode') == 0) and error != 'auth_info_error'
    
    def _parse_response(self, response: requests.Response) -> Optional[Dict]:
        """解析登录响应"""
        try:
            text = response.text.strip()
            content_type = response.headers.get('Content-Type', '').lower()
            
            if 'text/html' in content_type or text.startswith(('<!DOCTYPE', '<html')):
                return {'success': False, 'message': '返回HTML页面，登录失败'}
            
            # 尝试解析JSON或JSONP
            data = None
            try:
                data = response.json()
            except:
                data = self._parse_jsonp(text)
            
            if data and isinstance(data, dict):
                success = self._check_success(data)
                return {
                    'success': success,
                    'message': data.get('ploy_msg' if success else 'error_msg', '登录成功' if success else '登录失败'),
                    'raw_response': data
                }
            
            # 解析文本响应
            text_lower = text.lower()
            if text_lower in ('ok', 'login_ok', 'success') or '登录成功' in text or '认证成功' in text:
                return {'success': True, 'message': text[:500]}
            elif '失败' in text or '错误' in text or 'error' in text_lower:
                return {'success': False, 'message': text[:500]}
            
            return {'success': False, 'message': text[:500] if text else f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'message': f'解析响应失败: {str(e)}'}
    
    def logout(self) -> Dict:
        """登出"""
        logout_data = {'action': 'logout', 'ac_id': self.ac_id}
        for url in [f"{self.service_ip}/cgi-bin/srun_portal", f"{self.service_ip}/api/portal/logout"]:
            try:
                if self.session.post(url, data=logout_data).status_code == 200:
                    return {'success': True, 'message': '登出成功'}
            except:
                continue
        return {'success': False, 'message': '登出失败'}


def load_config(config_file: str = "config.json") -> Dict:
    """加载配置文件"""
    if not os.path.exists(config_file):
        print(f"错误: 配置文件 {config_file} 不存在")
        print(f"请创建 {config_file} 文件，参考 config.json.example")
        sys.exit(1)
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError as e:
        print(f"错误: 配置文件格式错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 读取配置文件失败: {e}")
        sys.exit(1)


def main():
    """主函数"""
    # 优先使用命令行指定的配置文件，否则使用默认的 config.json
    config_file = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].endswith('.json') else "config.json"
    
    # 加载配置
    config = load_config(config_file)
    
    # 从配置中读取参数
    username = config.get('username', '')
    password = config.get('password', '')
    domain = config.get('domain', '1- @ynufe')
    service_ip = config.get('service_ip', 'http://172.16.130.31')
    ac_id = config.get('ac_id', 7)
    
    # 验证必需参数
    if not username or not password:
        print("错误: 配置文件中缺少 username 或 password")
        sys.exit(1)
    
    # 执行登录
    print(f"正在登录 {domain}...")
    print(f"用户名: {username}")
    result = CampusNetworkLogin(service_ip, ac_id).login(username, password, domain)
    
    print("\n" + "="*50)
    print("✓ 登录成功！" if result.get('success') else "✗ 登录失败")
    print(f"信息: {result.get('message', '无详细信息')}")
    print("="*50)
    
    if 'raw_response' in result:
        print("\n详细响应:")
        print(json.dumps(result['raw_response'], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

