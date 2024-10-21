package com.chensoul.oauth2.controller;

import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class ArticleRestController {

    @GetMapping("/resource/article")
    public List<String> article() {
        return Arrays.asList("article1", "article2", "article3");
    }
}
