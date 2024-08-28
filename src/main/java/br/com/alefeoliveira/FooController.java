package br.com.alefeoliveira;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FooController {

	@GetMapping("/public")
	public ResponseEntity<String> publicRoute(){
		return ResponseEntity.ok("PublicRoute ok");
	}
	
	@GetMapping("/private")
	public ResponseEntity<String> privateRoute(){
		return ResponseEntity.ok("PublicRoute ok");
	}
	
	@GetMapping("/user")
	public ResponseEntity<Message> user(Authentication authentication){
		return ResponseEntity.ok(new Message("Heelo"+ authentication.getName()));
	}
}
