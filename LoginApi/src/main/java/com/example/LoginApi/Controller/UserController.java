package com.example.LoginApi.Controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.LoginApi.Entity.User;
import com.example.LoginApi.Repository.UserRepository;
import com.mongodb.DuplicateKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@RestController
public class UserController {

    private KeyPair serverKeyPair;
    private byte[] sharedSecretKey;
    public static final String PUBLIC_KEY_FILE_PATH ="C:\\Users\\Mahesh\\Login\\LoginApi\\src\\main\\resources\\keystore\\publicKey";
	public static final String PRIVATE_KEY_FILE_PATH = "C:\\Users\\Mahesh\\Login\\LoginApi\\src\\main\\resources\\keystore\\privateKey";
	 @Autowired
	    private UserRepository userRepository;
	    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @GetMapping("/initiateKeyExchange")
    public ResponseEntity<String> initiateKeyExchange() {
        try {
            // Generate the server's public/private key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGenerator.initialize(2048);
            serverKeyPair = keyPairGenerator.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            saveKey(serverPrivateKey.getEncoded(),PRIVATE_KEY_FILE_PATH);
            // Return the server's public key to the client
            byte[] publicKeyBytes = serverPublicKey.getEncoded();
            saveKey(publicKeyBytes,PUBLIC_KEY_FILE_PATH );
            String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
            return ResponseEntity.ok(publicKeyBase64);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to initiate key exchange.");
        }
    }
    

    @PostMapping("/signup")
    public ResponseEntity<String> signupUser (@RequestParam String clientPublicKeyBase64, @RequestBody User user) {
        try {        	   
              byte[] sharedSecretKey = generateSecretKey(clientPublicKeyBase64);         
            
            // Decrypt the username and password using the shared secret key
            String decryptedUsername = decrypt(sharedSecretKey, user.getEmail());
            String decryptedPassword = decrypt(sharedSecretKey, user.getPassword());
            
            //Store in Database
            storeUserInformation(decryptedUsername, decryptedPassword);
            
            return ResponseEntity.ok("User successfully signed up.");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
                NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("User Login Failed");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("User already exists.");
        }
    }
    public byte[] generateSecretKey(String clientPublicKeyBase64) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
        PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
        byte[] serverPrivateBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE_PATH));
        x509KeySpec = new X509EncodedKeySpec(serverPrivateBytes);
        PrivateKey serverPrivateKey = keyFactory.generatePrivate(x509KeySpec);
        keyAgreement.init(serverPrivateKey);
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecretKey = keyAgreement.generateSecret();
		return sharedSecretKey;
    }
    @SuppressWarnings("unused")
	@PostMapping("/login")
    public ResponseEntity<String> checkIfUserExists(@RequestParam String clientPublicKey, @RequestBody User user) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	byte[] sharedSecretKey = generateSecretKey(clientPublicKey);         
        
        // Decrypt the username and password using the shared secret key
        String decryptedUsername = decrypt(sharedSecretKey, user.getEmail());
        String decryptedPassword = decrypt(sharedSecretKey, user.getPassword());
        User current_user = userRepository.findByUsername(decryptedUsername);
        if(user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found.");
        }
        String encryptedPassword = current_user.getPassword();
        if(passwordEncoder.matches(decryptedPassword, encryptedPassword)) {
        	String sessionId = createSession(user.getEmail());
            user.setSessionId(sessionId);
            userRepository.save(user);
            return ResponseEntity.ok().body(sessionId);
        }
        else{
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password.");
        }    	
    	
    }
    private String createSession(String userId) {
        String sessionId = UUID.randomUUID().toString();
        return sessionId;
    }
    

    private String decrypt(byte[] sharedSecretKey, String encryptedData) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecretKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedDataBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedDataBytes, StandardCharsets.UTF_8);
    }

    private void storeUserInformation(String username, String password) throws Exception {
        try {
            // Encrypt the password before saving the user to the database
            String encryptedPassword = passwordEncoder.encode(password);
            User user = new User();
            user.setEmail(username);
            user.setPassword(encryptedPassword);
            userRepository.save(user);
        } catch (Exception e) {
            throw new Exception("User already exists.");
        }
    }


    private void saveKey(byte[] sharedSecretKey, String path) throws IOException {
        String sharedSecretString = Base64.getEncoder().encodeToString(sharedSecretKey);
    	File f = new File(path);
		f.getParentFile().mkdirs();
		System.out.println("i created a file in ");
		System.out.println(path);
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(sharedSecretString.getBytes());
		fos.flush();
		fos.close();
	}
    
}

