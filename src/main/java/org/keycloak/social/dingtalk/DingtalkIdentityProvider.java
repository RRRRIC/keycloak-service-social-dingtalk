/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.dingtalk;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Locale;


/**
 * @author Jinxin
 * created at 2022/1/12 16:25
 */
public class DingtalkIdentityProvider extends AbstractOAuth2IdentityProvider<DingtalkProviderConfig> implements SocialIdentityProvider<DingtalkProviderConfig> {

    public static final String SNS_URL = "https://oapi.dingtalk.com/connect/oauth2/sns_authorize";
    public static final String OAUTH2_URL = "https://login.dingtalk.com/oauth2/auth";
    public static final String PROFILE_URL = "https://oapi.dingtalk.com/sns/getuserinfo_bycode";
    public static final String DEFAULT_SCOPE = "";

    public static final String DINGTALK_OAUTH2_CODE = "authCode";

    private static final String snsScope = "snsapi_auth";
    private static final String oauth2Scope = "openid corpid";

    public static final String DINGTALK_PARAMETER_CORP_ID = "corpId";
    public static final String DINGTALK_PARAMETER_APP_ID = "appid";

    public static final String PROFILE_UNIONID = "unionid";
    public static final String PROFILE_BOSS = "boss";
    public static final String PROFILE_ROLE_LIST = "role_list";
    public static final String PROFILE_MANAGER_USERID = "manager_userid";
    public static final String PROFILE_ADMIN = "admin";
    public static final String PROFILE_REMARK = "remark";
    public static final String PROFILE_TITLE = "title";
    public static final String PROFILE_HIRED_DATE = "hired_date";
    public static final String PROFILE_USERID = "userid";
    public static final String PROFILE_WORK_PLACE = "work_place";
    public static final String PROFILE_DEPT_LIST = "dept_list";
    public static final String PROFILE_REAL_AUTHED = "real_authed";
    public static final String PROFILE_DEPT_ID_LIST = "dept_id_list";
    public static final String PROFILE_JOB_NUMBER = "job_number";
    public static final String PROFILE_EMAIL = "email";
    public static final String PROFILE_MOBILE = "mobile";
    public static final String PROFILE_ACTIVE = "active";
    public static final String PROFILE_TELEPHONE = "telephone";
    public static final String PROFILE_AVATAR = "avatar";
    public static final String PROFILE_SENIOR = "senior";
    public static final String PROFILE_NAME = "name";
    public static final String PROFILE_STATE_CODE = "state_code";
    public static final String PROFILE_ORG_EMAIL = "org_email";
    public static final String PROFILE_NICKNAME = "nickname";

    public DingtalkIdentityProvider(KeycloakSession session, DingtalkProviderConfig config) {
        super(session, config);
        config.setOAuth2Url(OAUTH2_URL);
        config.setSnsUrl(SNS_URL);
        config.setUserInfoUrl(PROFILE_URL);
        config.setSnsScope(snsScope);
        config.setOauth2Scope(oauth2Scope);
        config.setDefaultScope(getDefaultScopes());
        logger.info("Dingtalk Provider OAuth2 url : " + config.getOAuth2Url());
        logger.info("Dingtalk Provider SNS url : " + config.getSnsUrl());
        logger.info("Dingtalk Provider OAuth2 scope  : " + config.getOauth2Scope());
        logger.info("Dingtalk Provider SNS scope : " + config.getSnsScope());
        logger.info("Dingtalk Provider ClientId  : " + config.getClientId());
        logger.info("Dingtalk Provider ClientSecret : " + config.getClientSecret());
        logger.info("Dingtalk Provider CorpId  : " + config.getCorpId());

    }


    /**
     * @param realm    ??????????????? realm
     * @param callback Authentication Callback ??????????????????
     * @param event    ???????????????
     * @return ???????????? callback ??????????????? ????????? Spring ?????? Controller ?????? RequestMapping
     * @see org.keycloak.broker.provider.IdentityProvider.AuthenticationCallback
     */
    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }


    /**
     * BrokeredIdentityContext ???????????? Keycloak ?????????????????? <br />
     * BrokeredIdentityContext ?????????????????????????????? <br />
     * ???????????? {@link org.keycloak.broker.provider.BrokeredIdentityContext#setUserAttribute(String, String)} ??????????????????????????????
     * <p>
     * <p>
     * ???????????? :
     * {"boss":false,"unionid":"lFSii0FnQ0PQZagpUxoEPmgiEiE",
     * "role_list":[{"group_name":"??????","name":"????????????","id":2396787909}],
     * "exclusive_account":false,"mobile":"158****7612","active":true,"admin":true,"remark":"","telephone":"",
     * "avatar":"","hide_mobile":false,"title":"","userid":"010317531219717","senior":false,"work_place":"",
     * "dept_order_list":[{"dept_id":1,"order":176275808490200512}],"real_authed":true,"name":"?????????","dept_id_list":[1],
     * "job_number":"","state_code":"86","email":"","leader_in_dept":[{"leader":false,"dept_id":1}]}
     * <p>
     * ?????????????????? https://open.dingtalk.com/document/orgapp-server/query-user-details
     *
     * @param event   ????????????
     * @param profile ????????? JsonNode ??????????????????
     * @return ????????? Keycloak ??????????????????
     * @see org.keycloak.broker.provider.BrokeredIdentityContext
     */
    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        logger.info("Received json Profile : " + profile);
        // unionid ???????????????
        String unionid = getJsonProperty(profile, PROFILE_UNIONID);
        BrokeredIdentityContext user = new BrokeredIdentityContext(unionid);

        String userId = getJsonProperty(profile, PROFILE_USERID);
        String name = getJsonProperty(profile, PROFILE_NICKNAME);
        if (DingtalkUtils.isBlank(name)) {
            name = getJsonListProperty(profile, PROFILE_NAME);
        }
        user.setUsername(userId);
        user.setBrokerUserId(userId);
        user.setModelUsername(name);

        String email = getJsonProperty(profile, PROFILE_ORG_EMAIL);
        if (DingtalkUtils.isBlank(email)) {
            email = getJsonProperty(profile, PROFILE_EMAIL);
            if (DingtalkUtils.isBlank(email)) {
                email = unionid + "@mail.default";
            }
        }
        user.setEmail(email);
        user.setFirstName(name);
        user.setLastName(email.toLowerCase().split("@")[0]);


        // ???????????? ID Union ID
        user.setUserAttribute(PROFILE_UNIONID, getJsonProperty(profile, PROFILE_UNIONID));

        // ???????????????
        user.setUserAttribute(PROFILE_BOSS, getJsonProperty(profile, PROFILE_BOSS));

        // ??????????????????????????????????????? name ??????
        user.setUserAttribute(PROFILE_ROLE_LIST, getJsonListProperty(profile.get(PROFILE_ROLE_LIST), "name"));

        // ?????????????????????
        user.setUserAttribute(PROFILE_MANAGER_USERID, getJsonProperty(profile, PROFILE_MANAGER_USERID));

        // ????????? Admin ?????????
        user.setUserAttribute(PROFILE_ADMIN, getJsonProperty(profile, PROFILE_ADMIN));

        // ??????
        user.setUserAttribute(PROFILE_REMARK, getJsonProperty(profile, PROFILE_REMARK));

        // ????????????
        user.setUserAttribute(PROFILE_TITLE, getJsonProperty(profile, PROFILE_TITLE));

        // ????????????
        if (profile.get(PROFILE_HIRED_DATE) != null) {
            long hiredTimeStamp = profile.get(PROFILE_HIRED_DATE).asLong();
            user.setUserAttribute(PROFILE_HIRED_DATE, DingtalkUtils.getDateStringByTimestamp(hiredTimeStamp));
        }
        // ????????????
        user.setUserAttribute(PROFILE_WORK_PLACE, getJsonProperty(profile, PROFILE_WORK_PLACE));

        // ????????????
        StringBuilder departmentListString = new StringBuilder();
        if (profile.get(PROFILE_DEPT_ID_LIST).isArray()) {
            for (JsonNode jsonNode : profile.get(PROFILE_DEPT_ID_LIST)) {
                JsonNode depInfoJson = DingtalkUtils.getDepartmentById(session,
                        getConfig().getClientId(),
                        getConfig().getClientSecret(),
                        jsonNode.asInt(1));
                if (depInfoJson != null) {
                    departmentListString.append(depInfoJson.get("name").asText()).append(",");
                }
            }
            if (departmentListString.length() >= 1) {
                departmentListString.deleteCharAt(departmentListString.length() - 1);
            }
        }
        user.setUserAttribute(PROFILE_DEPT_LIST, departmentListString.toString());

        // ????????????
        user.setUserAttribute(PROFILE_REAL_AUTHED, getJsonProperty(profile, PROFILE_REAL_AUTHED));

        // ????????????
        user.setUserAttribute(PROFILE_JOB_NUMBER, getJsonProperty(profile, PROFILE_JOB_NUMBER));

        // ?????????????????????????????????158xxxx7612
        user.setUserAttribute(PROFILE_MOBILE, getJsonProperty(profile, PROFILE_MOBILE));

        // ??????????????????
        user.setUserAttribute(PROFILE_ACTIVE, getJsonProperty(profile, PROFILE_ACTIVE));

        // ????????? 010-8xxxx6-2345
        user.setUserAttribute(PROFILE_TELEPHONE, getJsonProperty(profile, PROFILE_TELEPHONE));

        // ??????
        user.setUserAttribute(PROFILE_AVATAR, getJsonProperty(profile, PROFILE_AVATAR));

        // ???????????????
        user.setUserAttribute(PROFILE_SENIOR, getJsonProperty(profile, PROFILE_SENIOR));

        // ??????????????????????????? ?????????86
        user.setUserAttribute(PROFILE_STATE_CODE, getJsonProperty(profile, PROFILE_STATE_CODE));

        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }


    /**
     * ??????????????? + clientId + clientSecret ???????????????????????????
     *
     * @param code SNS ?????????
     * @return ????????? Keycloak ????????????????????????
     */
    public BrokeredIdentityContext getFederatedIdentityBySNS(String code) {
        try {
            JsonNode userinfoJson;
            String clientId = getConfig().getClientId();
            String clientSecret = getConfig().getClientSecret();


            String unionId = DingtalkUtils.getUserUnionIdBySns(session, clientId, clientSecret, code);
            userinfoJson = DingtalkUtils.getUserInfoByUnionId(session, clientId, clientSecret, unionId);

            return extractIdentityFromProfile(null, userinfoJson);

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from dingtalk." + e.getMessage(), e);
        }
    }


    /**
     * ??????????????? + clientId + clientSecret ???????????????????????????
     *
     * @param code OAuth2 ?????????
     * @return ????????? Keycloak ????????????????????????
     */
    public BrokeredIdentityContext getFederatedIdentityByOAuth2(String code) {
        try {
            JsonNode userinfoJson;
            String clientId = getConfig().getClientId();
            String clientSecret = getConfig().getClientSecret();

            // ?????? OAuth2 ????????????
            String accessToken = DingtalkUtils.getUserAccessTokenByOAuth2Code(session, clientId, clientSecret, code);
            userinfoJson = DingtalkUtils.getUserInfoByUserAccessToken(session, clientId, clientSecret, accessToken);

            return extractIdentityFromProfile(null, userinfoJson);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from dingtalk." + e.getMessage(), e);
        }
    }


    /**
     * ???????????????????????????????????????????????????
     * ?????????????????? Response.seeOther ??????
     *
     * @param request ????????????
     * @return 302 ????????? response
     * @see javax.ws.rs.core.Response#seeOther(URI)
     */
    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            logger.info("auth url " + authorizationUrl.toString());
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            throw new IdentityBrokerException("Could not create authentication request. ", e);
        }
    }


    /**
     * @return ????????? scope
     */
    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    /**
     * ??????????????????????????????????????????????????????
     * ?????????????????????????????????????????? SNS ?????????????????????????????????
     * ?????????????????????????????????????????? OAuth2 ??????
     * ?????? user-agent ??????????????? dingtalk
     *
     * @param request ????????????
     * @return ??????????????????
     */
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        String userAgent = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase(Locale.ROOT);
        if (userAgent.contains("dingtalk")) {
            // ???????????????????????????????????????
            return UriBuilder.fromUri(getConfig().getSnsUrl())
                    .queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getSnsScope())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(DINGTALK_PARAMETER_APP_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        } else {
            // ??????????????????????????? OAuth2 ??????
            return UriBuilder.fromUri(getConfig().getOAuth2Url())
                    .queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getOauth2Scope())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                    .queryParam(DINGTALK_PARAMETER_CORP_ID, getConfig().getCorpId())
                    .queryParam("prompt", "consent");
        }
    }


    /**
     * ???????????? OAuth2 ????????? CallBack Endpoint
     * ?????????????????????
     */
    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        /**
         * Endpoint ????????? callback ????????? <br />
         * ????????????????????????????????????????????????????????? IDP ?????????????????????????????? Response ??? IdpContext ??? <br />
         * ??????????????????????????????????????? Attribute ??? <br />
         *
         * @param state      state?????????
         * @param snsCode    SNS ???????????????
         * @param oauth2Code OAuth2 ?????????
         * @param error      ?????????????????? Error
         * @return ???????????? token ??????????????????
         */
        @GET
        public Response authResponse(@QueryParam(OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(OAUTH2_PARAMETER_CODE) String snsCode,
                                     @QueryParam(DINGTALK_OAUTH2_CODE) String oauth2Code,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (error != null) {
                logger.error(error + " for broker login " + getConfig().getProviderId());
                if (error.equals(ACCESS_DENIED)) {
                    return callback.cancelled(state);
                } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                    return callback.error(state, error);
                } else {
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }
            try {
                event.client(getConfig().getClientId());
                BrokeredIdentityContext federatedIdentity;

                if (!DingtalkUtils.isBlank(snsCode)) {
                    federatedIdentity = getFederatedIdentityBySNS(snsCode);
                } else {
                    if (!DingtalkUtils.isBlank(oauth2Code)) {
                        federatedIdentity = getFederatedIdentityByOAuth2(oauth2Code);
                    } else {
                        throw new Exception("Receive empty code");
                    }
                }

                // ????????? state ????????? code ??? ????????????????????? ??????????????????
                // ??? code ?????????????????? code??? ?????? state
                federatedIdentity.setCode(state);
                federatedIdentity.setIdpConfig(getConfig());
                federatedIdentity.setIdp(DingtalkIdentityProvider.this);
                event.user(federatedIdentity.getBrokerUserId());
                event.client(getConfig().getClientId());
                return callback.authenticated(federatedIdentity);

            } catch (WebApplicationException e) {
                logger.error(e.getMessage(), e);
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        user.setUsername(context.getUsername());
        user.setEmail(context.getEmail());
        user.setFirstName(context.getFirstName());
        user.setLastName(context.getLastName());

        user.setSingleAttribute(PROFILE_UNIONID, context.getUserAttribute(PROFILE_UNIONID));
        user.setSingleAttribute(PROFILE_BOSS, context.getUserAttribute(PROFILE_BOSS));
        user.setSingleAttribute(PROFILE_ROLE_LIST, context.getUserAttribute(PROFILE_ROLE_LIST));
        user.setSingleAttribute(PROFILE_MANAGER_USERID, context.getUserAttribute(PROFILE_MANAGER_USERID));
        user.setSingleAttribute(PROFILE_ADMIN, context.getUserAttribute(PROFILE_ADMIN));
        user.setSingleAttribute(PROFILE_REMARK, context.getUserAttribute(PROFILE_REMARK));
        user.setSingleAttribute(PROFILE_TITLE, context.getUserAttribute(PROFILE_TITLE));
        user.setSingleAttribute(PROFILE_HIRED_DATE, context.getUserAttribute(PROFILE_HIRED_DATE));
        user.setSingleAttribute(PROFILE_WORK_PLACE, context.getUserAttribute(PROFILE_WORK_PLACE));
        user.setSingleAttribute(PROFILE_DEPT_LIST, context.getUserAttribute(PROFILE_DEPT_LIST));
        user.setSingleAttribute(PROFILE_REAL_AUTHED, context.getUserAttribute(PROFILE_REAL_AUTHED));
        user.setSingleAttribute(PROFILE_JOB_NUMBER, context.getUserAttribute(PROFILE_JOB_NUMBER));
        user.setSingleAttribute(PROFILE_MOBILE, context.getUserAttribute(PROFILE_MOBILE));
        user.setSingleAttribute(PROFILE_ACTIVE, context.getUserAttribute(PROFILE_ACTIVE));
        user.setSingleAttribute(PROFILE_TELEPHONE, context.getUserAttribute(PROFILE_TELEPHONE));
        user.setSingleAttribute(PROFILE_AVATAR, context.getUserAttribute(PROFILE_AVATAR));
        user.setSingleAttribute(PROFILE_SENIOR, context.getUserAttribute(PROFILE_SENIOR));
        user.setSingleAttribute(PROFILE_STATE_CODE, context.getUserAttribute(PROFILE_STATE_CODE));
    }


    @Override
    public String getJsonProperty(JsonNode jsonNode, String name) {
        if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            String s = jsonNode.get(name).asText();
            if (s != null && !s.isEmpty())
                return s;
            else
                return "";
        }
        return "";
    }

    public String getJsonListProperty(JsonNode jsonNode, String fieldName) {
        if (!jsonNode.isArray()) {
            return getJsonProperty(jsonNode, fieldName);
        }
        StringBuilder sb = new StringBuilder();
        for (JsonNode node : jsonNode) {
            sb.append(getJsonProperty(node, fieldName)).append(",");
        }
        if (sb.length() >= 1) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    public String getJsonProperty(JsonNode jsonNode, String name, String defaultValue) {
        if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            String s = jsonNode.get(name).asText();
            if (s != null && !s.isEmpty())
                return s;
            else
                return defaultValue;
        }

        return defaultValue;
    }
}
