package se.digg.eudiw.issuer_tests.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class TestIndexController {

    @GetMapping("/test-index")
    public String testIndex(Model model) {

        List<String> testCases = List.of("start-test-1-authorisation-flow", "start-test-2-pre-authorisation-flow", "start-test-3-par");
        model.addAttribute("testCases", testCases);
        return "test-index";
    }
}
