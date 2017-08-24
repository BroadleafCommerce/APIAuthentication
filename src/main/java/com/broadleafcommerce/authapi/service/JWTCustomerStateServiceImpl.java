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

import org.broadleafcommerce.common.crossapp.service.CrossAppAuthService;
import org.broadleafcommerce.profile.core.domain.Customer;
import org.broadleafcommerce.profile.core.service.CustomerService;
import org.broadleafcommerce.profile.core.service.CustomerUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import com.broadleafcommerce.authapi.domain.RegisterDTO;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Nick Crum ncrum
 */
@Service("blJWTCustomerStateService")
@ConditionalOnProperty(name = "blc.auth.jwt.enabled")
public class JWTCustomerStateServiceImpl implements CustomerStateService {

    protected final Environment environment;
    protected final CustomerService customerService;
    protected final JWTTokenService jwtTokenService;

    @Autowired(required = false)
    @Qualifier("blCrossAppAuthService")
    protected CrossAppAuthService crossAppAuthService;

    public JWTCustomerStateServiceImpl(Environment environment, CustomerService customerService, JWTTokenService jwtTokenService) {
        this.environment = environment;
        this.customerService = customerService;
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public Customer registerNewCustomer(RegisterDTO registerDTO) {
        Customer registeredCustomer = customerService.createNewCustomer();
        registeredCustomer.setEmailAddress(registerDTO.getEmailAddress());
        registeredCustomer.setUsername(registerDTO.getEmailAddress());
        registeredCustomer.setFirstName(registerDTO.getFirstName());
        registeredCustomer.setLastName(registerDTO.getLastName());
        return customerService.registerCustomer(registeredCustomer, registerDTO.getPassword(), registerDTO.getConfirmPassword());
    }

    @Override
    public Customer getCustomer(HttpServletRequest request) {
        Customer customer = getAuthenticatedCustomer();

        // if the customer was not found from the Authentication
        if (customer == null) {

            // 1. get the customer token from request
            String customerToken = getCustomerTokenFromRequest(request);

            if (customerToken != null) {

                // 2. parse the token to get the customer id
                Long customerId = jwtTokenService.parseCustomerToken(customerToken);

                if (customerId != null) {

                    // 3. get the customer
                    Customer customerByToken = customerService.readCustomerById(customerId);
                    if (customerByToken != null) {

                        // 4. Check if customer is anonymous or verify the customer matches the CustomerUserDetails
                        if (!customerByToken.isRegistered() || isCrossAppAuthenticated()) {
                            customer = customerByToken;
                        }
                    }
                }
            }
        }

        if (customer == null) {
            // if no customer is found, create a new temporary anonymous customer (don't save)
            customer = customerService.createNewCustomer();
            customer.setAnonymous(true);
        }

        if (customer.isRegistered()) {
            customer.setLoggedIn(true);
        }

        return customer;
    }

    protected boolean isCrossAppAuthenticated() {
        if (crossAppAuthService == null) {
            return false;
        }
        return crossAppAuthService.isAuthedFromAdmin() && crossAppAuthService.hasCsrPermission();
    }

    protected Customer getAuthenticatedCustomer() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof CustomerUserDetails) {
            return customerService.readCustomerById(((CustomerUserDetails) authentication.getPrincipal()).getId());
        }
        return null;
    }

    protected String getCustomerTokenFromRequest(HttpServletRequest request) {
        if (request.getHeader(getCustomerTokenHeader()) != null) {
            return request.getHeader(getCustomerTokenHeader());
        }
        return request.getParameter(getCustomerTokenRequestParameter());
    }

    protected String getCustomerTokenHeader() {
        return environment.getProperty("blc.auth.jwt.customer.header");
    }

    protected String getCustomerTokenRequestParameter() {
        return environment.getProperty("blc.auth.jwt.customer.param");
    }
}
