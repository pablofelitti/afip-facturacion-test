package ar.com.afip.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@Controller
public class MainController {

    @RequestMapping("/")
    public String index(Map<String, Object> model) {

        model.put("message", "Hello world!");

        return "index";
    }
}
