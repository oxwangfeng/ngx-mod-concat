ngx-mod-concat
====
合并多个文件在一个响应报文中。
ngx_http_concat_module只支持本地文件concat，此模块做到从上游服务器资源合并。

京东首页用例

http://misc.360buyimg.com/??jdf/lib/jquery-1.6.4.js,jdf/1.0.0/ui/ui/1.0.0/ui.js

天猫首页用例

//g.alicdn.com/??mui/global/1.3.9/global.css,tm/fp/3.1.3/css/index.css

实现

  rewrite阶段使用子请求方式实现


过程

  过滤需要解析的url，分解成多个单个的资源
  使用nginx子请求，并发请求upstream
  合并资源，回传给browser


指令

jinx_concat
syntax: jinx_concat on|off
default: -
context: http, server
