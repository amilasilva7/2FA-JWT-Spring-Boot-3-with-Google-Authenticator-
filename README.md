# Spring Boot 3.0 Security with JWT Implementation

This project demonstrates the implementation of security using Spring Boot 3.0 and JSON Web Tokens (JWT). It includes
the following features:

## Features

* User registration and login with JWT authentication
* Password encryption using BCrypt
* Role-based authorization with Spring Security
* Customized access denied handling
* Logout mechanism
* Refresh token

## Technologies

* Spring Boot 3.0
* Spring Security
* JSON Web Tokens (JWT)
* BCrypt
* Maven

## Getting Started

To get started with this project, you will need to have the following installed on your local machine:

* JDK 17+
* Maven 3+

To build and run the project, follow these steps:

* Unzip the zip file
* Navigate to the project directory: cd spring-boot-security-jwt
* Add database "jwt_security" to postgres
* Build the project: mvn clean install
* Run the project: mvn spring-boot:run

-> The application will be available at http://localhost:8080.

Open the Postman and import collection file and postman environment file (Goto: src/main/resources/...):

* You must initially register with details, and you will get an image URL (GA(Google Authenticator) QR for registration) as the response.
* Scan that QR using your Google authenticator, and it will register with your GA.
* Complete the registration step 2 with a new GA code.
* You can log using your username and password and GA code.[Login with TOTP]
* Once you logged in you can access secured APIs.(Management APIs and admin APIs)
* You can change the password.
* You can log out and you will no longer access to secured APIs.