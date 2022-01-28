package org.keycloak.social.dingtalk;

import com.fasterxml.jackson.databind.JsonNode;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 用于钉钉用户信息获取的通用方法
 *
 * @author Jinxin
 * created at 2022/1/12 17:39
 **/
public class DingtalkUtils {

    public static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:ss:mm");

    private static final Logger logger = Logger.getLogger(DingtalkUtils.class);

    private final static String userUnionIdUrl = "https://oapi.dingtalk.com/sns/getuserinfo_bycode";
    private final static String corAccessTokenUrl = "https://oapi.dingtalk.com/gettoken";
    private final static String userIdByCorAccessUrl = "https://oapi.dingtalk.com/topapi/user/getbyunionid";
    private final static String userInfoByIdUrl = "https://oapi.dingtalk.com/topapi/v2/user/get";
    private final static String userAccessTokenByOAuth2CodeUrl = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken";
    private final static String userinfoByUserAccessTokenUrl = "https://api.dingtalk.com/v1.0/contact/users/me";
    private final static String departmentInfoByIdUrl = "https://oapi.dingtalk.com/topapi/v2/department/get";

    private final static String userAccessTokenHeader = "x-acs-dingtalk-access-token";


    private static DefaultCacheManager _cacheManager;
    public static String DINGTALK_CACHE_NAME = "DINGTALK_CACHE";
    public static Cache<String, String> DingtalkCache = get_cache();

    private static final String DINGTALK_CORP_ACCESS_TOKEN = "DINGTALK_CORP_ACCESS_TOKEN";


    /**
     * 有小概率验证返回失败，当前未能发现错误 <br />
     * 官方签名 Demo {@link DingtalkUtils#getSignature(String, String)} <br />
     * 官方连接 https://open.dingtalk.com/document/orgapp-server/obtain-the-user-information-based-on-the-sns-temporary-authorization
     *
     * @param session      当前的 Keycloak Session
     * @param clientId     clientId
     * @param clientSecret clientSecret
     * @param code         SNS 授权码
     * @return 用户的 union ID
     */
    public static String getUserUnionIdBySns(KeycloakSession session,
                                             String clientId,
                                             String clientSecret,
                                             String code) throws Exception {

        JsonNode responseJson;
        for (int i = 2; i >= 0; i--) {
            String timestamp = new Date().getTime() + "";
            String urlEncodeSignature = DingtalkUtils.getSignature(clientSecret, timestamp);
            String snsUrl = userUnionIdUrl + "?" +
                    "accessKey=" + clientId +
                    "&timestamp=" + timestamp +
                    "&signature=" + urlEncodeSignature;
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("tmp_auth_code", code);
            responseJson = SimpleHttp.doPost(snsUrl, session).json(requestBody).asJson();
            if (requestBody.get("errcode") != null || responseJson.get("errcode").asInt(-1) != 0) {
                logger.warn("Failed to get user union id by sns,request Url : " + snsUrl + " response : " + responseJson);
                continue;
            }
            logger.info("Sns request Url : " + snsUrl);
            logger.info(responseJson);
            return responseJson.get("user_info").get("unionid").asText();
        }
        throw new Exception("Failed to get user union id by sns");
    }

    /**
     * 官方连接 https://open.dingtalk.com/document/orgapp-server/obtain-orgapp-token
     *
     * @param session      当前的 Keycloak Session
     * @param clientId     企业的 appID
     * @param clientSecret 企业的 appSecret
     * @return 企业的 access token
     */
    public static String getCorAccessToken(KeycloakSession session,
                                           String clientId,
                                           String clientSecret) throws Exception {

        String corAccessToken = DingtalkCache.get(DINGTALK_CORP_ACCESS_TOKEN + clientId);
        if (!isBlank(corAccessToken)) {
            return corAccessToken;
        }
        String accessTokenUrl = corAccessTokenUrl + "?" +
                "appkey=" + clientId +
                "&appsecret=" + clientSecret;
        JsonNode responseJson = SimpleHttp.doGet(accessTokenUrl, session).asJson();
        if (responseJson.get("errcode") != null && responseJson.get("errcode").asInt(-1) != 0) {
            logger.warn("Failed to get cor id, response : " + responseJson);
            throw new Exception("Failed to get cor id");
        }
        logger.info(responseJson);
        corAccessToken = responseJson.get("access_token").asText();
        int expireIn = responseJson.get("expires_in").asInt(0);
        expireIn = (int) (expireIn * 0.9);
        DingtalkCache.put(DINGTALK_CORP_ACCESS_TOKEN + clientId, corAccessToken, expireIn, TimeUnit.SECONDS);
        return corAccessToken;
    }

    /**
     * 官方链接 https://open.dingtalk.com/document/orgapp-server/logon-free-third-party-websites
     *
     * @param session   当前的 Keycloak Session
     * @param appId     企业的 appID
     * @param appSecret 企业的 appSecret
     * @param unionId   用户的联合 ID
     * @return 用户信息的 JsonNode
     */
    public static JsonNode getUserInfoByUnionId(KeycloakSession session,
                                                String appId,
                                                String appSecret,
                                                String unionId) throws Exception {

        String corAccessToken = getCorAccessToken(session, appId, appSecret);
        if (isBlank(corAccessToken)) {
            throw new Exception("Can't get cor access token");
        }
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("unionid", unionId);
        String getUserIdByCorAccessUrl = userIdByCorAccessUrl + "?access_token=" + corAccessToken;
        JsonNode responseJson = SimpleHttp.doPost(getUserIdByCorAccessUrl, session).json(requestBody).asJson();
        if (responseJson.get("errcode") != null && responseJson.get("errcode").asInt(-1) != 0) {
            logger.warn("Failed to get user id by union id, response : " + responseJson);
            throw new Exception("Failed to get user id by union id");
        }
        logger.info(responseJson);
        String userId = responseJson.get("result").get("userid").asText();
        return getUserInfoByUserID(session, corAccessToken, userId);
    }

    /**
     * 官方链接 https://open.dingtalk.com/document/orgapp-server/query-user-details
     *
     * @param corAccessToken 企业的 access token
     * @param userId         用户ID
     * @return 用户信息的 JsonNode
     * @see DingtalkUtils#getCorAccessToken(KeycloakSession, String, String)
     */
    public static JsonNode getUserInfoByUserID(KeycloakSession session,
                                               String corAccessToken,
                                               String userId) throws Exception {

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("userid", userId);
        String userInfoUrl = userInfoByIdUrl + "?access_token=" + corAccessToken;
        JsonNode responseJson = SimpleHttp.doPost(userInfoUrl, session).json(requestBody).asJson();
        if (responseJson.get("errcode") != null && responseJson.get("errcode").asInt(-1) != 0) {
            logger.warn("Failed to get userinfo by user id : " + responseJson);
            throw new Exception("Failed to get userinfo by user id");
        }
        logger.info(responseJson);
        return responseJson.get("result");
    }


    /**
     * 此方法为复合方法 <br />
     * 首先通过用户的 {@link DingtalkUtils#getUserAccessTokenByOAuth2Code(KeycloakSession, String, String, String)}
     * access token 获取 union ID   <br />
     * 再根据 Union Id 获取到用户信息
     * {@link DingtalkUtils#getUserInfoByUnionId(KeycloakSession, String, String, String)}
     * <p>
     * 获取用户 unionId 的官方链接 https://open.dingtalk.com/document/orgapp-server/dingtalk-retrieve-user-information
     *
     * @param session         当前的 Keycloak Session
     * @param appId           appId 跟 clientID 一致
     * @param appSecret       appSecret， 跟 clientSecret 一致
     * @param userAccessToken 用户的 access token
     * @return 用户信息的 JsonNode
     */
    public static JsonNode getUserInfoByUserAccessToken(KeycloakSession session,
                                                        String appId,
                                                        String appSecret,
                                                        String userAccessToken) throws Exception {
        JsonNode responseJson = SimpleHttp.doGet(userinfoByUserAccessTokenUrl, session)
                .header(userAccessTokenHeader, userAccessToken).asJson();
        if (responseJson.get("errcode") != null && responseJson.get("errcode").asInt(-1) != 0) {
            logger.warn("Failed to get userinfo by user access token : " + responseJson);
            throw new Exception("Failed to get userinfo by user access token");
        }
        logger.info(responseJson);
        String unionId = responseJson.get("unionId").asText();
        return getUserInfoByUnionId(session, appId, appSecret, unionId);
    }


    /**
     * 官方链接 : https://open.dingtalk.com/document/isvapp-server/obtain-identity-credentials
     *
     * @param session      当前的 Keycloak Session
     * @param clientId     clientID
     * @param clientSecret clientSecret
     * @param code         OAuth2 授权码
     * @return 用户的 access token
     */
    public static String getUserAccessTokenByOAuth2Code(KeycloakSession session,
                                                        String clientId,
                                                        String clientSecret,
                                                        String code) throws Exception {

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("clientId", clientId);
        requestBody.put("clientSecret", clientSecret);
        requestBody.put("code", code);
        requestBody.put("grantType", "authorization_code");
        JsonNode responseJson = SimpleHttp.doPost(userAccessTokenByOAuth2CodeUrl, session)
                .header("Content-Type", "application/json")
                .json(requestBody)
                .asJson();
        if (responseJson.get("accessToken") == null) {
            logger.warn("Failed to get user access token by oauth2 code : " + responseJson);
            throw new Exception("Failed to get user access token by oauth2 code");
        }
        return responseJson.get("accessToken").asText();
    }


    /**
     * 官方链接 : https://open.dingtalk.com/document/orgapp-server/query-department-details0-v2
     *
     * @param session      当前的 Keycloak Session
     * @param clientId     clientID
     * @param clientSecret clientSecret
     * @param departmentId 部门 ID
     * @return 部门信息的 JSON Node
     */
    public static JsonNode getDepartmentById(KeycloakSession session,
                                             String clientId,
                                             String clientSecret,
                                             int departmentId) {
        try {
            String corAccessToken = getCorAccessToken(session, clientId, clientSecret);
            if (isBlank(corAccessToken)) {
                logger.warn("Can't get cor access token");
                return null;
            }
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("dept_id", departmentId);
            String url = departmentInfoByIdUrl + "?access_token=" + corAccessToken;
            JsonNode responseJson = SimpleHttp.doPost(url, session)
                    .header("Content-Type", "application/json")
                    .json(requestBody)
                    .asJson();
            if (responseJson.get("errcode") != null && responseJson.get("errcode").asInt(-1) != 0) {
                logger.warn("Failed to get department info  : " + responseJson);
                return null;
            }
            logger.info(responseJson);
            return responseJson.get("result");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 用于签名企业的 app secret
     * 会自对签名后的数据进行 url encode
     * 官方地址 ： https://open.dingtalk.com/document/personalapp-server/signature-calculation-for-logon-free-scenarios-1
     *
     * @param appSecret 企业的 app secret
     * @param timestamp 加密时间戳
     * @return 被 url encode 过后的签名
     */
    public static String getSignature(String appSecret, String timestamp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(appSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] signatureBytes = mac.doFinal(timestamp.getBytes(StandardCharsets.UTF_8));
            String signature = new String(Base64.getEncoder().encode(signatureBytes), StandardCharsets.UTF_8);
            return urlEncode(signature, StandardCharsets.UTF_8.toString());
        } catch (Exception e) {
            logger.warn(e.getMessage(), e);
            return "";
        }
    }


    public static String urlEncode(String value, String charset) {
        if (value == null) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(value, charset);
            return encoded.replace("+", "%20").replace("*", "%2A")
                    .replace("~", "%7E").replace("/", "%2F");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("FailedToEncodeUri", e);
        }
    }

    public static boolean isBlank(String s) {
        if (s == null || s.length() < 1) {
            return true;
        }
        for (char c : s.toCharArray()) {
            if (c != ' ') {
                return false;
            }
        }
        return true;
    }

    public static String getDateStringByTimestamp(long timestamp) {
        try {
            Date date = new Date(timestamp);
            return dateFormat.format(date);
        } catch (Exception e) {
            return String.valueOf(timestamp);
        }
    }

    private static DefaultCacheManager getCacheManager() {
        if (_cacheManager == null) {
            ConfigurationBuilder config = new ConfigurationBuilder();
            _cacheManager = new DefaultCacheManager();
            _cacheManager.defineConfiguration(DINGTALK_CACHE_NAME, config.build());
        }
        return _cacheManager;
    }

    private static Cache<String, String> get_cache() {
        try {
            return getCacheManager().getCache(DINGTALK_CACHE_NAME);
        } catch (Exception e) {
            logger.error(e);
            e.printStackTrace(System.out);
            throw e;
        }
    }
}
