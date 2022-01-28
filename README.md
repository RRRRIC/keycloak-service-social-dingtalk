# keycloak-services-social-dingtalk

Keycloak dingtalk 授权登录增强插件


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
> 2.基于新版钉钉 API 2022/01/27


