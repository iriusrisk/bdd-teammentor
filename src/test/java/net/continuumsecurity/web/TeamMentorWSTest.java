package net.continuumsecurity.web;

import com.securityinnovation.teammentor.SoapActionInterceptor;
import https.teammentor_securityinnovation_com._13415.TMUser;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.Cookie;
import org.tempuri.NewUser;
import org.tempuri.TMWebServices;
import org.tempuri.TMWebServicesSoap;

import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

/**
 * ****************************************************************************
 * BDD-Security, application security testing framework
 * <p/>
 * Copyright (C) `2012 Stephen de Vries`
 * <p/>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see `<http://www.gnu.org/licenses/>`.
 * ****************************************************************************
 */
public class TeamMentorWSTest {
    private static final QName SERVICE_NAME = new QName("http://tempuri.org/", "TM_WebServices");
    TMWebServicesSoap port;
    TMUser currentUser;
    TMWebServices ss;

    @Before
    public void setup() {
        URL wsdlURL = TMWebServices.WSDL_LOCATION;
        ss = new TMWebServices(wsdlURL, SERVICE_NAME);
        port = ss.getTMWebServicesSoap();
        Client client = ClientProxy.getClient(port);
        client.getEndpoint().getOutInterceptors().add(new SoapActionInterceptor());
        HTTPConduit http = (HTTPConduit) client.getConduit();
        HTTPClientPolicy httpClientPolicy = new HTTPClientPolicy();
        httpClientPolicy.setProxyServer("localhost");
        httpClientPolicy.setProxyServerPort(8080);
        httpClientPolicy.setAllowChunking(false);
        http.setClient(httpClientPolicy);
        ((BindingProvider)port).getRequestContext().put(BindingProvider.SESSION_MAINTAIN_PROPERTY, true);


        port.loginPwdInClearText("admin", "tmadmin");
        setCSRFToken();

        try {
            TMUser bob = port.getUserByName("bobster");
            if (bob != null) port.deleteUser(bob.getUserID());
        } catch (Exception e) {
            System.out.println("No existing user found, no need to delete.");
        }
        port.logout();

    }

    private void setCSRFToken() {
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        headers.put("CSRF_Token", Arrays.asList(port.currentUser().getCSRFToken()));
        ClientProxy.getClient(port).getRequestContext().put(Message.PROTOCOL_HEADERS, headers);
    }

    public void printDetails() {
        currentUser = port.currentUser();
        System.out.println(currentUser.getFirstName() + " " + currentUser.getLastName());
        System.out.println("Group ID: " + currentUser.getGroupID());
        System.out.println(port.currentSessionID());
    }

    //@Test
    public void testLoginOk() {
        port.loginPwdInClearText("admin", "!!tmadmin");
        printDetails();
        assertEquals("John",currentUser.getFirstName());
        port.logout();

        port.loginPwdInClearText("reader", "!!tmreader");
        printDetails();
        assertEquals("Peter",currentUser.getFirstName());
        port.logout();

        port.loginPwdInClearText("editor", "!!tmeditor");
        printDetails();
        assertEquals("Joe",currentUser.getFirstName());
        port.logout();
    }

    //@Test
    public void testGetUserRoles() {
        port.loginPwdInClearText("admin", "!!tmadmin");
        for (String role : port.getCurrentUserRoles().getString()) {
            System.out.println("Role: "+role);
        }
    }

    //@Test
    public void testGetUserByName() {
        port.loginPwdInClearText("admin", "!!tmadmin");
        setCSRFToken();
        port.loginPwdInClearText("admin", "!!tmadmin");
        setCSRFToken();
        TMUser user = port.getUserByName("reader");
        assertEquals("Peter",user.getFirstName());

        user = port.getUserByName("editor");
        assertEquals("Joe",user.getFirstName());

        port.logout();
    }

    //@Test
    public void testListUsers() {
        port.loginPwdInClearText("reader", "tmreader");
        setCSRFToken();
        port.getUsers();
    }

    //@Test
    public void testGetCookieByName() {
        port.loginPwdInClearText("reader","tmreader");
        Client client = ClientProxy.getClient(port);
        client.getEndpoint().getOutInterceptors().add(new SoapActionInterceptor());
        HTTPConduit http = (HTTPConduit) client.getConduit();
        for (String name : http.getCookies().keySet()) {
            System.out.println("index name: "+name+" cookiename: "+http.getCookies().get(name).getName()+" value: "+http.getCookies().get(name).getValue());
        }
    }


    public Cookie getCookieByName(String name) {
        Client client = ClientProxy.getClient(port);
        client.getEndpoint().getOutInterceptors().add(new SoapActionInterceptor());
        HTTPConduit http = (HTTPConduit) client.getConduit();
        if (http.getCookies() == null || http.getCookies().size() == 0) return null;
        org.apache.cxf.transport.http.Cookie cookie = http.getCookies().get(name);
        Cookie returnCookie = new Cookie(cookie.getName(),cookie.getValue(),cookie.getPath());
        return returnCookie;
    }

    //@Test
    public void testCreateArticle() {
        port.loginPwdInClearText("editor", "tmeditor");
        setCSRFToken();
        //System.out.println(port.getLibraries().getTMLibrary().get(0).getId());
        port.createArticleSimple("4738d445-bc9b-456c-8b35-a35057596c16","title test","String","<h1>A test</h1>");
    }

    @Test
    public void createUser() {
        String t = "blahhello1blah";
        Pattern p = Pattern.compile("hello\\d");
        System.out.println(p.matcher(t).find());

        port.loginPwdInClearText("reader", "tmreader");
        setCSRFToken();
        NewUser user = new NewUser();
        user.setEmail("test@test.com");
        user.setFirstname("bob");
        user.setLastname("bobster");
        user.setUsername("bobster");
        user.setGroupId(2);
        port.createUser(user);
        TMUser createdUser = port.getUserByName("bobster");
    }

    //@Test
    public void testEditUser() {
        port.loginPwdInClearText("admin", "!!tmadmin");
        setCSRFToken();
        List<TMUser> users = port.getUsers().getTMUser();
        assertTrue(users.size() > 1);
        users = port.getUsers().getTMUser();
        //user.setFirstName("bob");
        //port.updateUser(user.getUserID(),user.getUserName(),user.getFirstName(),user.getLastName(),user.getTitle(),user.getCompany(),user.getEMail(),user.getGroupID());
        port.logout();
    }
}
