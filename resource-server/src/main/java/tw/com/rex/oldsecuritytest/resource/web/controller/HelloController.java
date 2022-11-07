package tw.com.rex.oldsecuritytest.resource.web.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class HelloController {

    @PostMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello~");
    }

}
