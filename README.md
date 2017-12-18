# README

## 客户端设置

host: 127.0.0.1

port: 10086

user: admin

password: password

具体设置方法见[proxy_config.pdf](proxy_config.pdf)

## 代理服务器设置

- [add_user.py](add_user.py)是添加用户和密码的脚本

-[rules](rules)文件夹存放的是用户对应的规则，采用`json`格式。规则文件命名格式为：`username.rule`。规则样例 ([admin.rule](rules/admin.rule)) ：

```json
{
    "cc.scu.edu.cn":"sw.scu.edu.cn",
    "jwc.scu.edu.cn":""
}
```

含义：

1. 将对`cc.scu.edu.cn`的访问重定向到`sw.scu.edu.cn`。

1. 禁止对`jwc.scu.edu.cn`的访问。

## 代理服务器运行方法

`python3 run_threaded.py`