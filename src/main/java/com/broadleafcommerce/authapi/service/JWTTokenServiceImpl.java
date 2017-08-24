/*-
 * #%L
 * BroadleafCommerce API Authentication
 * %%
 * Copyright (C) 2009 - 2017 Broadleaf Commerce
 * %%
 * Licensed under the Broadleaf End User License Agreement (EULA), Version 1.1
 * (the "Commercial License" located at http://license.broadleafcommerce.org/commercial_license-1.1.txt).
 * 
 * Alternatively, the Commercial License may be replaced with a mutually agreed upon license (the "Custom License")
 * between you and Broadleaf Commerce. You may not use this file except in compliance with the applicable license.
 * 
 * NOTICE:  All information contained herein is, and remains
 * the property of Broadleaf Commerce, LLC
 * The intellectual and technical concepts contained
 * herein are proprietary to Broadleaf Commerce, LLC
 * and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Broadleaf Commerce, LLC.
 * #L%
 */
package com.broadleafcommerce.authapi.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import com.broadleafcommerce.authapi.domain.JWTUserDTO;
import java.util.Date;

/**
 * @author Nick Crum ncrum
 */
@Service("blJWTTokenService")
@ConditionalOnProperty(name = "blc.auth.jwt.enabled")
public class JWTTokenServiceImpl implements JWTTokenService {

    protected final Environment environment;

    @Autowired
    public JWTTokenServiceImpl(Environment environment) {
        this.environment = environment;
    }

    @Override
    public JWTUserDTO parseAuthenticationToken(String token) throws ExpiredJwtException {
        return parseTokenUsingSecret(token, getAuthenticationSecret());
    }

    @Override
    public JWTUserDTO parseRefreshToken(String token) throws ExpiredJwtException {
        return parseTokenUsingSecret(token, getRefreshSecret());
    }

    protected JWTUserDTO parseTokenUsingSecret(String token, String secret) throws ExpiredJwtException {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();

            JWTUserDTO dto = new JWTUserDTO();
            dto.setUsername(claims.getSubject());
            dto.setUserId(claims.get("userId", Integer.class).longValue());
            dto.setCrossAppAuth(claims.get("isCrossAppAuth", Boolean.class));
            dto.setRole(claims.get("role", String.class));

            return dto;
        } catch (UnsupportedJwtException | SignatureException | IllegalArgumentException | MalformedJwtException e) {
            return null;
        }
    }

    /**
     * This method is responsible for taking the token subject and generating the correct JWT authentication token.
     * @return the JWT token
     */
    @Override
    public String generateAuthenticationToken(Long userId, String username, boolean isCrossAppAuth, String commaSeparatedAuthorities) {
        Claims claims = Jwts.claims()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + getAuthenticationTokenExpirationTime()));
        claims.put("userId", userId);
        claims.put("isCrossAppAuth", isCrossAppAuth);
        if (commaSeparatedAuthorities != null) {
            claims.put("role", commaSeparatedAuthorities);
        }
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, getAuthenticationSecret())
                .compact();
    }

    @Override
    public String generateRefreshToken(Long userId, String username, boolean isCrossAppAuth, String commaSeparatedAuthorities) {
        Claims claims = Jwts.claims()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + getRefreshTokenExpirationTime()));
        claims.put("userId", userId);
        claims.put("isCrossAppAuth", isCrossAppAuth);
        if (commaSeparatedAuthorities != null) {
            claims.put("role", commaSeparatedAuthorities);
        }
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, getRefreshSecret())
                .compact();
    }

    @Override
    public Long parseCustomerToken(String customerToken) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getCustomerSecret())
                    .parseClaimsJws(customerToken)
                    .getBody();
            return Long.valueOf(claims.getSubject());
        } catch (ExpiredJwtException | UnsupportedJwtException | SignatureException | IllegalArgumentException | MalformedJwtException e) {
            return null;
        }
    }

    @Override
    public String generateCustomerToken(Long customerId) {
        Claims claims = Jwts.claims()
                .setSubject(String.valueOf(customerId))
                .setExpiration(new Date(System.currentTimeMillis() + getCustomerTokenExpirationTime()));
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, getCustomerSecret())
                .compact();
    }

    protected Long getAuthenticationTokenExpirationTime() {
        return environment.getProperty("blc.auth.jwt.access.expiration", Long.class);
    }

    protected String getAuthenticationSecret() {
        return environment.getProperty("blc.auth.jwt.access.secret");
    }

    protected Long getRefreshTokenExpirationTime() {
        return environment.getProperty("blc.auth.jwt.refresh.expiration", Long.class);
    }

    protected String getRefreshSecret() {
        return environment.getProperty("blc.auth.jwt.refresh.secret");
    }

    protected Long getCustomerTokenExpirationTime() {
        return environment.getProperty("blc.auth.jwt.customer.expiration", Long.class);
    }

    protected String getCustomerSecret() {
        return environment.getProperty("blc.auth.jwt.customer.secret");
    }
}
