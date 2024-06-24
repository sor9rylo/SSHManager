# SSHManager
Linux SSH 支持使用密钥连接测试，批量生成、添加、删除密钥，关闭开启ssh密码登录

## 测试环境

- Python 3.12.3
- CentOS 8
- Ubuntu 22.04
- Debian 12

## 功能

> 生成密钥

> 添加密钥（支持密钥方式）

> 测试使用密钥连接

> 删除选择的密钥

> 删除所有密钥

> 关闭SSH密码登录

> 开启SSH密码登录

### 服务器信息配置格式

用户不填默认：root，端口不填默认：22
> ip/domain,password,user,port


### 运行
> pip install paramiko PyQt5

> python main.py
