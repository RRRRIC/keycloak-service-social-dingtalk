# keycloak-dingtalk-idp

**对应博客详解 https://www.cnblogs.com/jinxin-c/articles/keycloak_dingtalk.html**

Keycloak dingtalk 授权登录增强插件

支持钉钉手机客户端内部的自动登录和外部浏览器的OAuth2登录


需要在钉钉中开放以下权限

-   个人手机号信息	
-   通讯录个人信息读权限	
-   调用SNS API时需要具备的基本权限	
-   企业员工手机号信息	
-   邮箱等个人信息	
-   通讯录部门信息读权限	
-   维护通讯录的接口访问权限	
-   成员信息读权限	
-   通讯录部门成员读权限	
-   调用企业API基础权限	
-   调用OpenApp专有API时需要具备的权限	




需要在 ${keycloak_home}/modules/system/layers/keycloak/org/keycloak/keycloak-services/main/module.xml
 中添加 infinispan 依赖。

```xml
    <dependencies>
        <module name="org.infinispan" services="import"/>
        ....
    </dependencies>
```

To build:
`mvn clean package`

To install the social dingtalk work one has to:

* Add the jar to the Keycloak server (create `providers` folder if needed):
  * `$ cp target/keycloak-services-social-dingtalk-{x.y.z}.jar _KEYCLOAK_HOME_/providers/` 

* Add config page templates to the Keycloak server:
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-dingtalk.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-dingtalk-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`

-----------------------------------------------------------------
特殊说明:
=========================================================
> 1.基于 Keycloak 12.0.4版本
>
> 2.基于新版钉钉 API 2022/01/27


