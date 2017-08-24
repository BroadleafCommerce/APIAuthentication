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

import org.broadleafcommerce.profile.core.domain.Customer;
import com.broadleafcommerce.authapi.domain.RegisterDTO;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Nick Crum ncrum
 */
public interface CustomerStateService {

    /**
     * Processes the {@code RegisterDTO} to create and register a new customer.
     *
     * @param registerDTO the object containing the new customer information
     */
    public Customer registerNewCustomer(RegisterDTO registerDTO);

    Customer getCustomer(HttpServletRequest request);
}
