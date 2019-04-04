/*
 * Copyright 2018 United Kingdom Research and Innovation
 * 
 * Licensed under the following BSD license:
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

package uk.ac.ceda.authentication.filter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.orp.app.cookie.DecryptionException;
import esg.orp.app.cookie.UserDetailsCookie;
import uk.ac.ceda.common.AccessControlFilter;

/**
 * Servlet Filter implementation class AuthRedirectFilter
 * 
 * @author William Tucker
 */
public class AuthenticationFilter extends AccessControlFilter
{

    private String sessionCookieName;
    private String secretKey;

    private final Log LOG = LogFactory.getLog(this.getClass());

    /**
     * @see Filter#destroy()
     */
    public void destroy() { }
    
    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // retrieve session cookie
        String cookieValue = null;
        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null)
        {
            for (Cookie cookie: cookies)
            {
                if (cookie.getName().equals(this.sessionCookieName))
                {
                    cookieValue = cookie.getValue();
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug(String.format("Found session cookie: %s", this.sessionCookieName));
                }
            }
        }
        
        if (cookieValue != null)
        {
            // determine userID from session cookie
            String userID = null;
            try
            {
                // parse a user ID from the cookie value
                UserDetailsCookie sessionCookie = UserDetailsCookie.parseCookie(
                        cookieValue,
                        this.secretKey);
                userID = sessionCookie.getUserID();
                
                if (LOG.isDebugEnabled())
                    LOG.debug(String.format("Found user ID: %s, cookie timestamp: %s",
                            userID, sessionCookie.getTimestamp()));
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException e)
            {
                LOG.error("Failed to load decoding/decryption handlers.", e);
            }
            catch (DecoderException | DecryptionException e)
            {
                if (LOG.isDebugEnabled())
                    LOG.debug(String.format("Problem parsing cookie value: %s", cookieValue), e);
            }
            
            if (userID == null)
            {
                LOG.warn("userID not found in cookie.");
            }
            else
            {
                // set request attribute indicating authentication success
                authenticateUser(request, userID);
            }
        }
        else if (LOG.isDebugEnabled())
        {
            LOG.debug(String.format(
                    "Session cookie (%s) not found. Skipping authentication.",
                    this.sessionCookieName));
        }
        
        // pass the request along the filter chain
        chain.doFilter(request, response);
    }
    
    /**
     * @see Filter#init(FilterConfig)
     */
    public void init(FilterConfig filterConfig) throws ServletException
    {
        ServletContext servletContext = filterConfig.getServletContext();
        
        String sessionCookieName = servletContext.getInitParameter(
                "sessionCookieName");
        if (sessionCookieName == null)
            LOG.error("Missing context parameter: sessionCookieName");
        this.setSessionCookieName(sessionCookieName);
        
        String sessionCookieSecret = servletContext.getInitParameter(
                "sessionCookieSecret");
        if (sessionCookieSecret == null)
            LOG.error("Missing context parameter: sessionCookieSecret");
        this.setSecretKey(sessionCookieSecret);
        
        if (sessionCookieName != null && sessionCookieSecret != null)
            LOG.info(String.format(
                    "Authentication Filter configured with cookie: %s",
                    this.sessionCookieName));
    }
    
    /**
     * Setter for sessionCookieName
     * 
     * @param sessionCookieName Name of the authentication service's authentication cookie
     */
    public void setSessionCookieName(String sessionCookieName)
    {
        this.sessionCookieName = sessionCookieName;
    }
    
    /**
     * Setter for secretKey
     * 
     * @param secretKey The secret key used to encyrpt the user authentication cookie
     */
    public void setSecretKey(String secretKey)
    {
        this.secretKey = secretKey;
    }

}
