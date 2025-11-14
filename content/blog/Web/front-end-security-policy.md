---
date: '2025-11-09T00:03:05+08:00'
title: '前端安全策略'
---

同源策略、跨域请求，对于这块的理解之前一直存在一些偏差，现在好好梳理一下。在后一篇文章中将介绍CSRF与这些前端安全策略的关系，并搭了一个简单的csrf-demo，感受下具体的影响。
<!--more-->

# SOP: 同源策略

## 同源的定义

Same Origin Policy 同源策略

**什么是同源**？如果两个URL的协议、端口、主机（域名）都相同，则认为两个URL是同源的。

同源策略的基本规则是：**一个源的脚本不能随意访问另一个源的 DOM、Cookie、LocalStorage、IndexedDB 等敏感数据，以及跨域请求的响应内容**（跨域请求可以发出去，但响应数据的读取通常会被浏览器拦截，除非目标服务器**明确通过 CORS** 等方式允许）

**DOM** （页面内容）：包括DOM结构、文本内容、输入框的值、Cookie、LocalStorage、SessionStorage、IndexedDB等

![image.png](%E5%89%8D%E7%AB%AF%E5%AE%89%E5%85%A8%E7%AD%96%E7%95%A5/image.png)

现代浏览器通常将使用 `file:///` 模式加载的文件的来源视为*不透明的来源*。这意味着，假如一个文件包括来自同一文件夹的其他文件，它们不会被认为来自同一来源，并可能引发 [CORS](https://developer.mozilla.org/zh-CN/docs/Glossary/CORS) 错误。

如果没有同源策略，前端Web应用会遭遇严重的问题

1. **防止敏感数据泄露**
    - 用户登录了 https://bank.com，浏览器里存有它的 Cookie。
    - 如果没有 SOP，恶意网站 http://evil.com 就能直接读取 bank.com 的 DOM 或 Cookie，窃取用户账号和资金信息。
2. **防止 CSRF 与恶意操作的升级**
    - 虽然跨站请求伪造（CSRF）攻击依然可能发起请求，但 SOP 至少保证了攻击者无法轻易获取响应结果，否则就能用“盲打+读结果”的方式精准利用漏洞。
3. **保障不同站点之间的隔离性**
    - 浏览器是用户访问互联网的核心入口，一个站点不应该能影响另一个站点的隐私与安全，否则任何网站都可能成为“恶意代理”。

**SOP是浏览器自身实现和强制执行的，可以理解为浏览器给每个网站加上了隔离沙箱**

- 默认情况下，你在 https://a.com 里写的 JS，看不到 https://b.com 的内部数据。
- **只有**在“墙的另一边”明确开了个窗（比如 CORS Response Header），你才能合法地探头过去。

浏览器会给每个网站维护自己的本地存储（Cookie、LocalStorage、IndexedDB、Cache API 等）。

- SOP 的一大作用就是阻止跨站脚本直接读写这些 **本地数据**。
    - 例如：evil.com 的 JS 无法直接读取 bank.com 的 LocalStorage 或 Cookie。
- CORS **不会改变这点**，因为 CORS 只管“跨域网络请求”，不影响本地缓存隔离？。

## 跨源网络访问

同源策略控制不同源之间的交互，例如在使用 [`XMLHttpRequest`](https://developer.mozilla.org/zh-CN/docs/Web/API/XMLHttpRequest) 或 [`<img>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/img) 标签时则会受到同源策略的约束。这些交互通常分为三类：

- 跨源**写操作**（Cross-origin writes）一般是被允许的。例如链接、重定向以及表单提交。特定少数的 HTTP 请求需要添加[预检请求](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Guides/CORS#%E9%A2%84%E6%A3%80%E8%AF%B7%E6%B1%82)。
- 跨源**资源嵌入**（Cross-origin embedding）一般是被允许的。
- 跨源**读操作**（Cross-origin reads）一般是不被允许的，但常可以通过内嵌资源来巧妙的进行读取访问。例如，你可以读取嵌入图片的高度和宽度，调用内嵌脚本的方法，或[得知内嵌资源的可用性](https://bugzil.la/629094)。

以下是可能嵌入跨源的资源的一些示例：

- 使用 `<script src="…"></script>` 标签嵌入的 JavaScript 脚本。语法错误信息只能被同源脚本中捕捉到。
- 使用 `<link rel="stylesheet" href="…">` 标签嵌入的 CSS。由于 CSS 的松散的语法规则，CSS 的跨源需要一个设置正确的 `Content-Type` 标头。如果样式表是跨源的，且 MIME 类型不正确，资源不以有效的 CSS 结构开始，浏览器会阻止它的加载。
- 通过 [`<img>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/img) 展示的图片。
- 通过 [`<video>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/video) 和 [`<audio>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/audio) 播放的多媒体资源。
- 通过 [`<object>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/object) 和 [`<embed>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/embed) 嵌入的插件。
- 通过 [`@font-face`](https://developer.mozilla.org/zh-CN/docs/Web/CSS/@font-face) 引入的字体。一些浏览器允许跨源字体（cross-origin fonts），另一些需要同源字体（same-origin fonts）。
- 通过 [`<iframe>`](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Elements/iframe) 载入的任何资源。站点可以使用 [`X-Frame-Options`](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Reference/Headers/X-Frame-Options) 标头来阻止这种形式的跨源交互。

### 如何允许跨源访问

可以使用CORS允许跨源访问，他是HTTP的一部分，允许服务端指定哪些主机可以从这个服务端加载资源。

跨域访问的方式主要有：

1. **CORS（主流、推荐）**
2. **跨源嵌入（script/img/iframe 等）**
3. **JSONP（旧方法）**
4. **postMessage（跨源通信）**
5. **反向代理（服务端层解决）**

### 如何阻止跨源访问

- CORS严格配置：阻止自己的资源被其他网站通过CORS访问
- CORP：阻止自己的资源被其他网站通过嵌入访问
- CSP：阻止自己的网站加载其他不可信来源的资源

# CORS: 跨域资源共享

SOP的核心是阻止跨域资源读取，但浏览器和标准同时提供了一些“开窗机制”，允许在安全可控的前提下进行跨域访问。这就是CORS：Cross Origin Resources Share

- **CORS 解决的是：跨域请求到服务器，能不能拿到数据？**
- **SOP 缓存隔离解决的是：不同网站之间，能不能直接偷浏览器里存的本地数据？**

## 核心思想

由 **服务器** 通过设置 HTTP 响应头来声明“哪些源可以访问我的数据”。
场景头部

```json
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Credentials: true
```

- 细节：
    - **简单请求**（GET、POST + 常见头）→ 直接发送。
    - **复杂请求**（比如 PUT、带自定义头）→ 浏览器会先发起 **预检请求（OPTIONS）**，确认服务器是否允许。

## 安全风险

### 服务器本身就是提供数据服务的，为什么还要用CORS限制访问呢？

1. 不是所有请求都是“用户主动发起的”
•	浏览器里，任何网站都能用 JS 发起跨域请求。
•	假设没有 CORS，用户只要打开一个恶意网站，它就能在后台偷偷请求你的银行接口、邮件接口，直接拿到返回的敏感数据。
•	CORS 的作用是：只有服务器信任的来源，才能读取响应数据，避免数据被“隔壁网站”偷走。
2. 数据和功能的边界问题
•	有的服务（如开放 API、CDN）确实是对所有人开放的 → 可以设置 Access-Control-Allow-Origin: *。
•	但大多数服务是只允许“特定前端站点”访问的，比如：
•	银行接口：只允许 [https://bank.com](https://bank.com/) 调用。
•	企业管理后台：只允许公司官网访问。
•	CORS 就是提供这种 可控的访问策略。

### SOP和CORS不能防止CSRF

**CORS 的核心点**：控制 **跨域请求的响应结果是否能被浏览器端 JavaScript 读取**。

SOP的核心点：控制浏览器本地缓存的各网站的**数据隔离**。

CSRF的本质：浏览器会在跨站请求时自动带上 Cookie/Session 等认证信息。

因此，即使 **SOP + CORS 都存在**，恶意网站依然可以：

- 发起跨域请求到 bank.com
- 浏览器会带上用户在 bank.com 的 Cookie
- bank.com 服务器看到 Cookie 是合法的，就执行了转账、改密码等操作
- 关键是：**CSRF 攻击并不依赖能否读到响应内容**，**它只要请求能发出、凭证**能带上就行。

### 服务器怎么知道一个请求是不是跨站的？

服务器判断跨站请求，只能靠 **浏览器传来的请求头**。

最常用的有：

1. Origin 头（POST、CORS 请求必带）
2. Referer 头（有时会缺失，但多数情况下能看到来源 URL）
3. Sec-Fetch-Site / Sec-Fetch-Mode / Sec-Fetch-Dest（现代浏览器自动加，能直接看出请求上下文是不是跨站）

所以服务器防御 CSRF 时，常见做法是校验：

- Origin 是否在白名单
- Referer 是否是本站域名
- 或结合 Sec-Fetch-Site 做进一步校验

### JS不能更改关键请求头

> 既然
> 

在浏览器里用 XMLHttpRequest 或 fetch 发请求时，开发者**只能设置部分安全允许的头部**。

- **允许设置的例子**：Content-Type, X-Requested-With, Authorization, 自定义的 X-...。
- **禁止修改的关键头部**（浏览器自动控制）：
    - Host
    - Origin
    - Referer
    - Cookie
    - Sec-Fetch-* 系列

换句话说：**JS 无法覆盖/伪造 Origin、Referer、Sec-Fetch-Site 这些头**。

虽然 JS 改不了这些头，但：

- **代理 / 中间件** 可能会篡改（比如 CDN、反向代理、Burp（需要先控制受害者的网络代理，或者目标站点的中间层））。
- **Referer** 可能缺失（隐私设置、HTTPS→HTTP 跳转会被剥掉）。
- **Origin** 只在特定请求里出现：
    - 必须是 **跨域的 XHR/fetch**，浏览器才会加 Origin。
    - 普通 GET 导航、图片请求可能没有。

# 其他跨域请求方法

前面提到，跨域请求的方法有如下几种

1. **CORS**
2. **跨源嵌入（script/img/iframe 等）**
3. **JSONP（旧方法）**
4. **postMessage（跨源通信）**
5. **反向代理（服务端层解决）**

也就是说，**其他几种跨域方式本身并不会受到 CORS 的约束，大体上只有「通过 XHR / fetch」这样的“主动请求+读响应”的场景，才会触发 CORS 检查，这是浏览器的机制。**

## **跨源嵌入（script/img/iframe 等）**

- **特点**：天然允许跨域加载，不走 CORS 验证。
- **限制**：加载可以执行/显示，但 JS 无法随便读取内容（比如 `<img>` 的像素、`<script>` 的代码执行结果可以跑，但源代码你读不到）。

如果这种方式不加以限制，那么就会造成安全隐患。

- `<script>`：如果引用来源不可信 → **XSS** 风险。
- `<img>`：可被用作 **CSRF 请求**（因为浏览器会带上 cookie）。
- `<iframe>`：可能造成 **点击劫持** 或恶意嵌套攻击。

```jsx
<!-- 跨域加载脚本 -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- 跨域加载样式 -->
<link rel="stylesheet" href="https://cdn.example.com/style.css">

<!-- 跨域加载图片 -->
<img src="https://images.example.com/logo.png" alt="logo">

<!-- 跨域嵌入 iframe -->
<iframe src="https://news.example.com" width="600" height="400"></iframe>
```

如何防范？

- 使用可信的 CDN、签名资源（Subresource Integrity, SRI）。即域名白名单
- 高风险接口不要用 GET（避免 <img> 被利用）。
- 页面响应头加 X-Frame-Options 或 Content-Security-Policy: frame-ancestors 防点击劫持。

## **JSONP（旧方法）**

**SOP 限制：**

- 本质是 <script> 加载 JS，不受 CORS 检查。
- 返回的内容必须是合法 JS（通常是函数调用）。

**安全隐患：**

- 服务端如果不严格处理 callback 参数 → **XSS 注入**。
- 仅支持 GET 请求，容易被利用。

**削减隐患：**

- 尽量废弃 JSONP，改用 CORS。
- 如果必须用，服务端严格校验 callback 参数，只允许字母数字下划线。
- 给返回加 Content-Type: application/javascript，避免误用。

```jsx
<script>
  function handleData(data) {
    console.log("返回的数据:", data);
  }
</script>
<script src="https://api.example.com/getUser?callback=handleData"></script>
```

**弃用 JSONP 的做法：**

1. 前端：不再通过 <script src="...&callback=fn"> 请求数据。
2. 服务端：改为返回 application/json，并正确设置 CORS 头：

## **postMessage（跨源通信）**

- postMessage **不受 SOP 限制**，任何窗口/iframe 都能互发消息。
- 但**接收方必须自己检查 event.origin** 才能安全使用。

如果接收方不校验来源，就可能被恶意页面伪造消息，导致敏感数据泄露或逻辑绕过。

[a.com](http://a.com/)

```jsx

<iframe id="child" src="https://b.com/page.html"></iframe>
<script>
  const iframe = document.getElementById("child");
  iframe.onload = () => {
    iframe.contentWindow.postMessage("hello from a.com", "https://b.com");
  };

  window.addEventListener("message", (e) => {
    if (e.origin === "https://b.com") {
      console.log("收到消息:", e.data);
    }
  });
</script>
```

b.com/page.html

```jsx
window.addEventListener("message", (e) => {
  if (e.origin === "https://a.com") {
    console.log("来自父页面:", e.data);
    e.source.postMessage("hi from b.com", e.origin);
  }
});
```

# CORP：跨域资源策略

**CORP (Cross-Origin Resource Policy)** 是浏览器的一种**响应头安全策略**，用来规定：

> 某个资源是否允许被其他源的页面加载。
> 

也就是说，它是站点在资源响应头里声明的“别人能不能跨域引用我”。

- **CORS**：解决 **请求端** 能不能读取跨域响应的问题（“别人能不能看我的”）。
- **CORP**：解决 **资源提供方** 能不能**被嵌入或引用**的问题（“别人能不能用我”）。

为什么会有CORP呢？因为**嵌入或引用**的场景**不会触发CORS，如果没有CORP，那么恶意网站通过嵌入方式绕过 CORS 去加载目标服务器的资源。**

他和CORS一样都是**对服务器资源的保护**

举个例子：

- bank.com 上的用户头像资源，如果响应头有 Cross-Origin-Resource-Policy: same-origin，那么即使 evil.com 想通过 <img src="https://bank.com/avatar.png"> 引用，也会被浏览器拒绝加载。

**如何配置？**

在HTTP响应头中设置

```
Cross-Origin-Resource-Policy: same-origin
```

常见取值：

- **same-origin**：只允许同源页面加载资源。
- **same-site**：允许同站（例如 a.example.com 和 b.example.com）加载。
- **cross-origin**：允许任何站点加载（相当于不启用保护）。

# 其他策略

## CSP: 内容安全策略

CORS、CORP都是对服务器资源的保护，CSP则是对客户端的保护。

- CORP：我能不能被别人用（嵌入引用）
- CORS：我能不能被别人读取（CORS跨域访问）
- CSP：我能不能用别人的东西

**CSP = 浏览器安全策略的“白名单”机制**

它是一组 HTTP 响应头，用来告诉浏览器：

- 哪些资源（脚本、样式、图片、iframe 等）可以被加载和执行；
- 哪些资源是禁止的。

目标：**降低 XSS、点击劫持、恶意外链** 等前端常见攻击的风险。

```jsx
Content-Security-Policy:
  default-src 'self';                # 默认只允许本站资源
  script-src 'self' 'nonce-r4nd0m';  # 仅本站脚本 + 带nonce的内联脚本
  style-src 'self' https://cdn.com;  # 样式可来自本站和CDN
  img-src 'self' data:;              # 图片允许本站和data URL
  frame-ancestors 'self';            # 禁止被第三方iframe嵌入
  connect-src 'self' https://api.com;# 限制 AJAX/WS/fetch 目标
```

## COOP

让你的页面**与其它源的顶级窗口分离进程**，阻断 window.open / window.opener 的跨源联系，防数据与对象被“邻居窗口”干扰。

```
Cross-Origin-Opener-Policy: same-origin | same-origin-allow-popups | unsafe-none
```

- same-origin：当前顶级页面与不同源的窗口**相互“断开”**（window.opener 变 null），防止跨站窗口投毒、数据窃取、Spectre 类侧信道干扰。
- same-origin-allow-popups：与上相同，但允许你打开的**同源**弹窗保留联系。
- unsafe-none（默认）：不隔离。

## COEP

**COEP（Cross-Origin Embedder Policy）**：要求页面里**所有跨源子资源**必须“可安全嵌入”（要么走 **CORS**，要么资源端有 **CORP**），否则**禁止加载**。

```
Cross-Origin-Embedder-Policy: require-corp | credentialless | unsafe-none
```

- require-corp：页面上**任何跨源子资源**（脚本、图片、字体、音视频、WASM、Worker 等）**必须**满足：
    - 走 **CORS** 且通过预检/允许；或
    - 资源端返回 **CORP**（如 Cross-Origin-Resource-Policy: same-site）。
        
        否则浏览器直接**阻止加载**。
        
- credentialless：以**无凭证模式**请求跨源资源（不带 Cookie/认证），降低信任门槛，部分场景更易达成隔离。
- unsafe-none（默认）：不强制。

# 总结

上述这些技术，其实都是在围绕着一个主题：**浏览器如何在“能互相访问资源”和“各网站相互隔离”之间做平衡**

前端安全的底座是 **同源策略（SOP）**：浏览器用「协议 + 域名 + 端口」定义“源”，默认禁止一个源的脚本访问另一个源的 DOM、Cookie、本地存储和 XHR/fetch 响应，只在有限场景下允许跨源写（链接、表单提交）和跨源嵌入（script/img/iframe 等）。这相当于给每个站点加了一道“沙箱墙”。

在这道墙上，浏览器提供了几类“开窗机制”：

- **CORS**：由服务器通过响应头声明哪些源可以读取自己的 HTTP 响应内容，只影响“JS 能不能读结果”，不改变本地缓存隔离，也防不了 CSRF。
- **跨源嵌入**：script/img/iframe 等标签天然允许加载其他源的资源，但 JS 通常读不到内容；如果不加约束，就会被用来做 XSS、CSRF、点击劫持。
- **JSONP / postMessage / 反向代理**：分别是旧时代的跨域读取方案、窗口/iframe 间的跨源通信方案，以及从服务端“绕过浏览器限制”的方案。

为弥补这些“开窗”带来的风险，又有了一组补强策略：

- **CORP**：资源端声明“谁可以嵌我”，防止别人用 <img>/<iframe> 等方式绕过 CORS 偷用资源。
- **CSP**：页面端声明“我可以加载谁”，通过白名单减少 XSS、恶意外链和点击劫持。
- **COOP / COEP**：把顶级页面与跨源窗口、子资源隔离到不同进程，只允许满足 CORS/CORP 条件的安全资源被嵌入，为高安全、高性能场景（如 SharedArrayBuffer）提供基础。

# REF

[https://tech.meituan.com/2018/10/11/fe-security-csrf.html](https://tech.meituan.com/2018/10/11/fe-security-csrf.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)