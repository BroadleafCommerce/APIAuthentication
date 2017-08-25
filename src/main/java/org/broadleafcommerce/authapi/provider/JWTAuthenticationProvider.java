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
import org.broadleafcommerce.authapi.domain.JWTAuthenticationToken;
import org.broadleafcommerce.authapi.domain.JWTUserDTO;
import org.broadleafcommerce.authapi.exception.ExpiredJWTAuthenticationException;
import org.broadleafcommerce.authapi.service.JWTTokenService;
import java.util.List;

/**
 * This provider is responsible for handling authentication for a {@code JWTAuthenticationToken} authentication.
 *
 * @author Nick Crum ncrum
 */
@Service("blJWTAuthenticationProvider")
@ConditionalOnProperty(value = "blc.auth.jwt.enabled", matchIfMissing = true)
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    protected final JWTTokenService jwtTokenService;

    protected final UserDetailsService userDetailsService;

    @Autowired
    public JWTAuthenticationProvider(JWTTokenService jwtTokenService, UserDetailsService userDetailsService) {
        this.jwtTokenService = jwtTokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JWTAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        JWTAuthenticationToken jwtAuthenticationToken = (JWTAuthenticationToken) authentication;
        JWTAuthenticationToken result = new JWTAuthenticationToken(
                principal, authentication.getCredentials(), user.getAuthorities(), jwtAuthenticationToken.getToken());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        JWTAuthenticationToken jwtAuthenticationToken = (JWTAuthenticationToken) authentication;
        String token = jwtAuthenticationToken.getToken();

        JWTUserDTO dto = null;
        try {
            dto = jwtTokenService.parseAuthenticationToken(token);
        } catch (ExpiredJwtException e) {
            throw new ExpiredJWTAuthenticationException(e);
        }

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
