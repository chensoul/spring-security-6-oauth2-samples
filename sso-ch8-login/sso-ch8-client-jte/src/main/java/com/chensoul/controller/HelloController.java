package com.chensoul.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class HelloController {

    @RequestMapping("/")
    public String index() {
        return "pages/home";
    }

    @RequestMapping("/login")
    public String login(Model model, String error) {
        if (error!=null) {
            model.addAttribute("error", true);
            model.addAttribute("errorMessage", "Invalid username or password");
        }

        return "pages/login";
    }
}
