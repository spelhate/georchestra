package org.georchestra.security;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class BlacklistProxyTargetsFilterTest {

    @Test
    public void testBlacklistProxyTargetsFilterGeneralCase() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("java.spironet.fr");
        ServletRequest req = new MockHttpServletRequest();
        ServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();

        bptf.doFilter(req, resp, f);

    }

    @Test
    public void testBlacklistProxyTargetsFilterWithUrlParam() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("java.spironet.fr");
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();
        req.setParameter("url", "https://java.spironet.fr");

        bptf.doFilter(req, resp, f);

    }

    @Test
    public void testBlacklistProxyTargetsFilterWithUrlParamAndSecProxy() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("java.spironet.fr");
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();
        req.setParameter("url", "https://java.spironet.fr");
        req.setRequestURI("/proxy/");

        bptf.doFilter(req, resp, f);

        assertTrue(resp.getStatus() == HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void testBlacklistProxyTargetsFilterWithUrlParamAndSecProxyWithoutSlash() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("java.spironet.fr");
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();
        req.setParameter("url", "http://java.spironet.fr");
        req.setRequestURI("/proxy");

        bptf.doFilter(req, resp, f);

        assertTrue(resp.getStatus() == HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void testBlacklistProxyTargetsFilterWithUrlBadlyFormattedUri() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("java.spironet.fr");
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();
        req.setParameter("url", "kgf lswdfkbj ftgbxdfklbnmxfjkgbn x wdjjkdf\nb\n\n\n.blah\u00a1");
        req.setRequestURI("/proxy/");

        bptf.doFilter(req, resp, f);

    }

    @Test
    public void testBlacklistProxyTargetsFilterWithIPAddress() throws IOException, ServletException {
        BlacklistProxyTargetsFilter bptf = new BlacklistProxyTargetsFilter("169.254.169.254");
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        FilterChain f = new MockFilterChain();
        req.setParameter("url", "http://169.254.169.254/rancher-metadata");
        req.setRequestURI("/proxy/");

        bptf.doFilter(req, resp, f);

    }

}
