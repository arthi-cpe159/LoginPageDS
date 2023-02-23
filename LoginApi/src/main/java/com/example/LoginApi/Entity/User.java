package com.example.LoginApi.Entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
  
	@Id
    private String email;

    private String password;

    private String publicKey;

    private String privateKey;
    
    private String sessionId;


    public User() {
    }

    public User(String email, String password, String publicKey, String privateKey) {
        this.email = email;
        this.password = password;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
   

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
    @Override
  	public String toString() {
  		return "User [email=" + email + ", password=" + password + ", publicKey=" + publicKey + ", privateKey="
  				+ privateKey + "]";
  	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
		
	}
	 public String getSessionId() {
	        return sessionId;
	    }

}

