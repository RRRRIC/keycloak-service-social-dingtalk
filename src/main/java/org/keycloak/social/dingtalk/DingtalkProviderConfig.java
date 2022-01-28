package org.keycloak.social.dingtalk;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.io.Serializable;

/**
 * CorID     为公司 ID
 * OAuth2Url 为 OAuth2 外部浏览器 URL
 * SnsUrl    为钉钉内部自动登录 URL
 *
 * @author Jinxin
 * created at 2022/1/12 19:46
 **/
public class DingtalkProviderConfig extends OAuth2IdentityProviderConfig implements Serializable {

    private static final String corpId = "corpId";
    private static final String oauth2Url = "Oauth2Url";
    private static final String snsUrl = "SnsUrl";
    private static final String snsScope = "SnsScope";
    private static final String oauth2Scope = "oauth2Scope";


    public DingtalkProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public DingtalkProviderConfig() {

    }

    public String getCorpId() {
        return getConfig().get(corpId);
    }


    public String getOAuth2Url() {
        return getConfig().get(oauth2Url);
    }

    public String getSnsUrl() {
        return getConfig().get(snsUrl);
    }

    public String getSnsScope() {
        return getConfig().get(snsScope);
    }

    public String getOauth2Scope() {
        return getConfig().get(oauth2Scope);
    }

    public void setCorpId(String corp) {
        getConfig().put(corpId, corp);
    }

    public void setOAuth2Url(String oauth2) {
        getConfig().put(oauth2Url, oauth2);
    }

    public void setSnsUrl(String sns) {
        getConfig().put(snsUrl, sns);
    }

    public void setSnsScope(String scope) {
        getConfig().put(snsScope, scope);
    }


    public void setOauth2Scope(String scope) {
        getConfig().put(oauth2Scope, scope);
    }
}
