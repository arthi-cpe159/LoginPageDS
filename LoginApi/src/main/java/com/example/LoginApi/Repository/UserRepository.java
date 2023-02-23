package com.example.LoginApi.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.LoginApi.Entity.User;

@Repository
public interface UserRepository extends MongoRepository<User, String> {

	User findByUsername(String emailId);
}