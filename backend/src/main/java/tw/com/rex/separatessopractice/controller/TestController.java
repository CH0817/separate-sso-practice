package tw.com.rex.separatessopractice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/test")
public class TestController {

    @PostMapping("/userDetails")
    public HttpEntity<UserDetails> userDetails() {
        return ResponseEntity.ok((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

}
