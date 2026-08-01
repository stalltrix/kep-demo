# kep 参考实现程序

<details>
<summary>config最小配置示例</summary>

```json
{
	"api_token": "[set your api_token]",
	"listen": "127.0.0.1:8080",
	"local_token": "[set your local_token]",
	"ntp": "time.cloudflare.com",
	"deny_file": "deny.json",
	"token_file": "token.json"
}

```

</details>

<br>

#### 更新：2026/08/01

0.3.2版本

- 支持自定义dns
- 支持自定义请求头

可通过"user_agent"自定义ua，"custom_dns"自定义dns。

自定义dns支持udp，doh，local file，留空即保持默认行为

<br>


---

#### 更新：2026/07/21

0.3.1版本

- 支持邻居节点自动熔断与健康检查

<br>


---

#### 更新：2026/07/04

0.3.0版本

- 支持custom public suffix list(psl)
- 支持跳过ssl验证
- 扩展更多tag
- 使用`-v`显示当前版本
- PSL寻址优化

使用`"custom_psl": "rule.txt"`可覆写psl，使用参考同目录`kep_psl.txt`

<br>


---


#### 更新：2026/05/29

0.2.9版本

- 优化索引生成

现已解决一个问题：index索引会频繁创建空索引，进行无效的系统调用，虽不影响最终逻辑。但可能造成性能浪费。

<br>


---

#### 更新：2026/04/08

0.2.3版本

- 重写了缓存逻辑

此次代码由非核心开发团队的社区成员提供，影响kep-edge 0.2.3+ 以及webui v0.1.7+

解决C100K下的爆环问题，降低内存占用，也许是过早优化。

<br>


---

#### 更新：2026/04/02

0.2.0版本积累更新

- 日志等级
- custom页面
- 其他重要更新

如果设置crt与key，那么自动启动tls

注意：local_token与token同等重要。

完整配置参考 `config.json`

<br>


---

#### 更新：2026/03/25

pkey吊销记录已实现，但是此吊销记录未按照原作者设计初衷实现，大概属于break change，还好现在网络小，好调头。

revocation record变成了allowlist。以降低未来可能导致的revocation记录无限膨胀问题。

需要现有节点添加pkey des摘要记录，确保pkey未被撤销

使用kep-cli可以快速获取当前pkey的des摘要值。

```bash
kep-cli -act des =pkey pkey
```

后一个是指定name，默认为"pkey"

dns txt填入摘要值"des=ea54d..."，可以填入多个pkey的

<br>

<details>
<summary></summary>

---

原作者的话:

> Knowledge-Exchange-Protocol(kep)诞生已经长达2年了，但是由于分布式论坛程序的复杂度，以及去中心的数据通信架构设计差异。在两年内一直不得寸进。开发十分缓慢，几乎要放弃，最终只留下文档。以及几乎不能用的参考实现程序。
> 
> 
> 十分感谢stalltrix大佬为首的团队，带来了一群壮汉，帮助我们完成了一个能正常上线的实现程序，也感谢的selinux大佬，3s1w大佬，huaxiong，no-passwd，skynet大佬，以及许多不想留下名字的大佬的debug测试，以及新组件的开发。
> 
> 感谢这些贡献的大佬，在以前原有的代码废墟上完成了并扩展kepcli工具。以及独立实现了kepweb的网页端程序。
> 
> 虽然其最终写出来的代码事实标准实现与原始文档存在不少冲突，但是相比这些，其做出完善程序的贡献更加重要。
> 
> 致谢：03/15/2026

</details>