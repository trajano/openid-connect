package net.trajano.openidconnect.sample;

import java.io.IOException;
import java.util.Date;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.provider.spi.KeyProvider;

@WebServlet(urlPatterns = "/login", loadOnStartup = 1)
@Stateless
public class LoginServlet extends HttpServlet {

    @EJB
    KeyProvider p;

    @Override
    protected void doGet(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        resp.getWriter()
                .print("hello world at " + new Date());
    }

    @PostConstruct
    public void init2() {

        System.out.println("init 2 " + p);
    }
}
