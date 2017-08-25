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
package org.broadleafcommerce.authapi.filter;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.broadleafcommerce.profile.core.service.CustomerUserDetails;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.broadleafcommerce.authapi.domain.JWTRefreshToken;
import org.broadleafcommerce.authapi.service.JWTTokenService;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This filter is responsible for retrieving a new access token using the refresh token from an HTTP-Only cookie.
 *
 * @author Nick Crum ncrum
 */
public class JWTRefreshTokenFilter extends AbstractAuthenticationProcessingFilter {

    protected final Environment environment;
    protected final JWTTokenService jwtTokenService;

    public JWTRefreshTokenFilter(String url, AuthenticationManager authenticationManager, Environment environment, JWTTokenService jwtTokenService) {
        super(url);
        this.environment = environment;
        this.jwtTokenService = jwtTokenService;
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {
        String refreshToken = getRefreshToken(req);
        if (refreshToken == null) {
            throw new AuthenticationServiceException("No refresh token provided");
        }

        JWTRefreshToken jwtRefreshToken = new JWTRefreshToken(refreshToken);

        return getAuthenticationManager().authenticate(jwtRefreshToken);
    }

    protected String getRefreshToken(HttpServletRequest request) {
        Cookie refreshTokenCookie = getRefreshTokenCookie(request);

        if (refreshTokenCookie != null) {
            return refreshTokenCookie.getValue();
        }

        return null;
    }

    protected Cookie getRefreshTokenCookie(HttpServletRequest request) {
        if (ArrayUtils.isEmpty(request.getCookies())) {
            return null;
        }

        for (Cookie cookie: request.getCookies()) {
            if (StringUtils.equals(cookie.getName(), getRefreshTokenCookieName())) {
                return cookie;
            }
        }

        return null;
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(auth);
        CustomerUserDetails customerUserDetails = (CustomerUserDetails) auth.getPrincipal();
        String authToken = jwtTokenService.generateAuthenticationToken(customerUserDetails.getId(), customerUserDetails.getUsername(), false, null);
        res.setHeader("Authorization", "Bearer " + authToken);
    }

    protected String getRefreshTokenCookieName() {
        return environment.getProperty("blc.auth.jwt.refresh.cookie.name");
    }
}
