# 校园网静默登录脚本

云南财经大学校园网自动登录工具，无需打开浏览器即可完成认证。

## 功能特点

- ✅ 静默登录，无需打开浏览器
- ✅ 支持配置文件，一键登录
- ✅ 自动获取本机IP和MAC地址
- ✅ 支持 教学/办公 和 宿舍/住宅 两种上网类型

## 使用方法

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置账号信息

复制示例配置文件：

```bash
cp config.json.example config.json
```

编辑 `config.json`，填入你的账号信息：

```json
{
  "username": "你的学号",
  "password": "你的密码",
  "domain": "1- @ynufe",
  "service_ip": "http://xxx.xxx.xxx.xxx",
  "ac_id": 7
}
```

**域名选项：**
- `1- @ynufe`：教学/办公上网
- `2- @ctc`：宿舍/住宅上网

### 3. 运行脚本

```bash
python login.py
```

## 技术说明

脚本实现了 SRUN 认证系统的完整登录流程：

1. **获取 Challenge**：从服务器获取随机 challenge 值
2. **密码加密**：使用 HMAC-MD5 对密码进行加密
3. **信息加密**：使用 XOR 加密算法对用户信息进行加密
4. **Base64 编码**：使用自定义 Base64 编码
5. **发送登录请求**：提交加密后的认证信息

## 注意事项


- ⚠️ 请妥善保管您的账号密码
- ⚠️ 不要在公共代码仓库中提交真实的账号密码
- ⚠️ 本脚本仅供学习和个人使用
- ⚠️ 使用前请确保符合学校网络使用规定


## 许可证

MIT License
