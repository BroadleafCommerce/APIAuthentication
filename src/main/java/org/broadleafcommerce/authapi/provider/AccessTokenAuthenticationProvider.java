/*-
 * #%L
 * BroadleafCommerce API Authentication
 * %%
 * Copyright (C) 2009 - 2017 Broadleaf Commerce
 * %%
 * Licensed under the Broadleaf Fair Use License Agreement, Version 1.0
 * (the "Fair Use License" located  at http://license.broadleafcommerce.org/fair_use_license-1.0.txt)
 * unless the restrictions on use therein are violated and require payment to Broadleaf in which case
 * the Broadleaf End User License Agreement (EULA), Version 1.1
 * (the "Commercial License" located at http://license.broadleafcommerce.org/commercial_license-1.1.txt)
 * shall apply.
 * 
 * Alternatively, the Commercial License may be replaced with a mutually agreed upon license (the "Custom License")
 * between you and Broadleaf Commerce. You may not use this file except in compliance with the applicable license.
 * #L%
 */
package org.broadleafcommerce.authapi.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.broadleafcommerce.authapi.domain.AccessTokenAuthentication;
import org.broadleafcommerce.authapi.domain.ApiUserDTO;
import org.broadleafcommerce.authapi.service.AuthenticationTokenService;
import java.util.List;

/**
 * This provider is responsible for handling authentication for a {@code AccessTokenAuthentication} authentication.
 *
 * @author Nick Crum ncrum
 */
@Service("blAccessTokenAuthenticationProvider")
public class AccessTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    protected final AuthenticationTokenService authenticationTokenService;

    protected final UserDetailsService userDetailsService;

    @Autowired
    public AccessTokenAuthenticationProvider(AuthenticationTokenService authenticationTokenService, UserDetailsService userDetailsService) {
        this.authenticationTokenService = authenticationTokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (AccessTokenAuthentication.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        AccessTokenAuthentication accessTokenAuthentication = (AccessTokenAuthentication) authentication;
        AccessTokenAuthentication result = new AccessTokenAuthentication(
                principal, authentication.getCredentials(), user.getAuthorities(), accessTokenAuthentication.getToken());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        AccessTokenAuthentication accessTokenAuthentication = (AccessTokenAuthentication) authentication;
        String token = accessTokenAuthentication.getToken();

        ApiUserDTO dto = authenticationTokenService.parseAccessToken(token);

        if (dto == null) {
            throw new AuthenticationServiceException("INVALID_ACCESS_TOKEN");
        }

        if (dto.isCrossAppAuth()) {
            List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(dto.getRole());
            return new User(String.valueOf(dto.getUserId()), "", true, true, true, true, authorities);
        } else {
            return userDetailsService.loadUserByUsername(dto.getUsername());
        }
    }



}
