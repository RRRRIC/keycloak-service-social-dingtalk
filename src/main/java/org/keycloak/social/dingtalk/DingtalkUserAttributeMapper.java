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

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * User attribute mapper.
 * 
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class DingtalkUserAttributeMapper extends AbstractJsonUserAttributeMapper {

	public static final String PROVIDER_ID = "dingtalk-user-attribute-mapper";
	private static final String[] cp = new String[] { DingtalkIdentityProviderFactory.PROVIDER_ID };

	@Override
	public String[] getCompatibleProviders() {
		return cp;
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	
    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
		user.setUsername(context.getUsername());
		user.setEmail(context.getEmail());
		user.setFirstName(context.getFirstName());
		user.setLastName(context.getLastName());

		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_UNIONID, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_UNIONID));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_BOSS, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_BOSS));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_ROLE_LIST, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_ROLE_LIST));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_MANAGER_USERID, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_MANAGER_USERID));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_ADMIN, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_ADMIN));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_REMARK, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_REMARK));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_TITLE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_TITLE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_HIRED_DATE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_HIRED_DATE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_WORK_PLACE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_WORK_PLACE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_DEPT_LIST, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_DEPT_LIST));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_REAL_AUTHED, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_REAL_AUTHED));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_JOB_NUMBER, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_JOB_NUMBER));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_MOBILE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_MOBILE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_ACTIVE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_ACTIVE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_TELEPHONE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_TELEPHONE));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_AVATAR, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_AVATAR));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_SENIOR, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_SENIOR));
		user.setSingleAttribute(DingtalkIdentityProvider.PROFILE_STATE_CODE, context.getUserAttribute(DingtalkIdentityProvider.PROFILE_STATE_CODE));

	}
	
}
