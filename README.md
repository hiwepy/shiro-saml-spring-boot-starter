# spring-boot-starter-shiro-saml
shiro starter for spring boot

### 说明


 > 基于 Shiro 的 Spring Boot Starter 实现

1. 基于OpenSMAL实现的认证整合

### Maven

``` xml
<dependency>
	<groupId>${project.groupId}</groupId>
	<artifactId>spring-boot-starter-shiro-saml</artifactId>
	<version>${project.version}</version>
</dependency>
```


OpenSAML提供了几种方式来实现SSO之间SAML数据传输。本文主要对HTTP Artifact Binding 做个简单介绍

#http://blog.csdn.net/MrSunnyCream/article/details/50913694

1.用户访问SP的受保护资源 
2.SP检查是否有用户的Session，如果用则直接访问 
3.如果没有Session上下文SP随机生成Artifact，并生成AuthnRequest 
如果在Cookie中发现票据信息，把票据信息放到AuthnRequest当中 
4.SP建立Artifact与AuthnRequest的关联信息 
5.SP重定向到IDP的接受Artifact接口，用Get方式发送Artifact，和SP在IDP中的注册ID 
6.IDP接受Artifact，然后用HTTP POST方式来请求SP的getAuthnRequest接口(参数为Artifact) 
7.SP 接受到IDP传过来的Artifact ，根据Artifact 把关联的AuthnRequest返回给IDP 
8.IDP接受到getAuthnRequest然后来验证AuthnRequest的有效性，检查 Status Version 等信息，如果Cookie中的票据不为空，则检查票据是否正确，是否在有效期内，如果票据为空，则重定向用户到登录页面来提交信息。 
9.如果票据正确或者用户通过输入用户名密码等信息通过验证，则IDP生成Artifact对象，IDP生成Response对象，并根据用户信息生成断言，同时对Response 中的 断言做签名处理，对票据对象做加密和签名处理，并把票据信息写入Cookie，并建立Artifact与Response的关联关系，并重定向浏览器到SP的getArtifact接口 
10. SP 接受到Artifact，并通过HTTP POST的方式把Artifact发送到IDP 
11. IDP通过Artifact找到关联的Response对象返回给SP 
12.SP接受到IDP传输过来的Response对象，首先对Response中的断言做验签操作，如果通过，则同意用户访问资源。

a：其实对于SP和IDP而言重要的信息其实是AuthnRequest和Response，只不过每次传输到浏览器的时候都是传递的是各自的引用，然后SP和IDP再更具饮用来获取 真实的数据。这样做安全性可能更高一点，但是增加了SP和IDP之间的通信。

b：其中用到的证书都是自己用OpenSSL自己制定。 
参考地址：http://blog.csdn.net/howeverpf/article/details/21622545

### Sample

[https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-shiro-saml](https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-sample-shiro-saml "spring-boot-sample-shiro-saml")

