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
package com.broadleafcommerce.authapi.provider;

import io.jsonwebtoken.ExpiredJwtException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import com.broadleafcommerce.authapi.domain.JWTRefreshToken;
import com.broadleafcommerce.authapi.domain.JWTUserDTO;
import com.broadleafcommerce.authapi.exception.ExpiredJWTAuthenticationException;
import com.broadleafcommerce.authapi.service.JWTTokenService;
import java.util.List;

/**
 * This provider is responsible for handling authentication for a {@code JWTAuthenticationToken} authentication.
 * This is generally only run when using the {@link com.broadleafcommerce.authapi.filter.JWTRefreshTokenFilter}
 * to verify the validity of the refresh token before generating a new access token for the user.
 *
 * @author Nick Crum ncrum
 */
@Service("blJWTRefreshAuthenticationProvider")
@ConditionalOnProperty("blc.auth.jwt.enabled")
public class JWTRefreshAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    protected final JWTTokenService jwtTokenService;
    protected final UserDetailsService userDetailsService;

    @Autowired
    public JWTRefreshAuthenticationProvider(JWTTokenService jwtTokenService, UserDetailsService userDetailsService) {
        this.jwtTokenService = jwtTokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JWTRefreshToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        JWTRefreshToken jwtAuthenticationToken = (JWTRefreshToken) authentication;
        JWTRefreshToken result = new JWTRefreshToken(
                principal, authentication.getCredentials(), user.getAuthorities(), jwtAuthenticationToken.getToken());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        JWTRefreshToken jwtAuthenticationToken = (JWTRefreshToken) authentication;
        String token = jwtAuthenticationToken.getToken();

        JWTUserDTO dto = null;
        try {
            dto = jwtTokenService.parseRefreshToken(token);
        } catch (ExpiredJwtException e) {
            throw new ExpiredJWTAuthenticationException(e);
        }

        if (dto == null) {
            throw new AuthenticationServiceException("INVALID_REFRESH_TOKEN");
        }

        if (dto.isCrossAppAuth()) {
            List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(dto.getRole());
            return new User(String.valueOf(dto.getUserId()), "", true, true, true, true, authorities);
        } else {
            return userDetailsService.loadUserByUsername(dto.getUsername());
        }
    }



}
