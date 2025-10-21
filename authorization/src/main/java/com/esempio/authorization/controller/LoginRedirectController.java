package com.esempio.authorization.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Controller
public class LoginRedirectController implements WebMvcConfigurer{

	@Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Rotte della SPA che devono restituire index.html
        registry.addViewController("/auth/login").setViewName("forward:/auth/index.html");
        registry.addViewController("/auth/register").setViewName("forward:/auth/index.html");
        // Se vuoi coprire anche un callback OAuth
        registry.addViewController("/auth/callback").setViewName("forward:/auth/index.html");
        // Aggiungi qui altre rotte “pulite” della SPA che vuoi forwardare
    }
}
