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

import org.broadleafcommerce.common.web.filter.AbstractIgnorableOncePerRequestFilter;
import org.broadleafcommerce.common.web.filter.FilterOrdered;
import org.broadleafcommerce.profile.core.domain.Customer;
import org.broadleafcommerce.profile.web.core.CustomerState;
import org.springframework.stereotype.Component;
import org.broadleafcommerce.authapi.service.CustomerStateService;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This filter runs after spring security and is responsible for setting up the customer state.
 * This will be automatically registered in post-security filter chain.
 *
 * @author Nick Crum ncrum
 */
@Component("blApiCustomerStateFilter")
public class ApiCustomerStateFilter extends AbstractIgnorableOncePerRequestFilter {

    public static final String BLC_RULE_MAP_PARAM = "blRuleMap";

    protected final CustomerStateService customerStateService;

    public ApiCustomerStateFilter(CustomerStateService customerStateService) {
        this.customerStateService = customerStateService;
    }

    @Override
    protected void doFilterInternalUnlessIgnored(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Customer customer = customerStateService.getCustomer(request);

        // Assuming the customer is found and either authenticated or anonymous, set the customer state
        if (customer != null) {
            CustomerState.setCustomer(customer);

            @SuppressWarnings("unchecked")
            Map<String,Object> ruleMap = (Map<String, Object>) request.getAttribute(BLC_RULE_MAP_PARAM);
            if (ruleMap == null) {
                ruleMap = new HashMap<>();
            }
            ruleMap.put("customer", customer);
            request.setAttribute(BLC_RULE_MAP_PARAM, ruleMap);
        }

        chain.doFilter(request,response);
    }

    @Override
    public int getOrder() {
        return FilterOrdered.POST_SECURITY_HIGH + 50;
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }
}
