# Whispr
A secure real-time chat application with AES/RSA encryption in Java.
This project was developed as part of a university Java course.  
## Authors
- **Przemysław Bukała** – (https://github.com/Przemekbukala)
- **Krzysztof Knap** – (https://github.com/kmka330)
##  Features
### Security
User registration and login (passwords are securely hashed using BCrypt).
End-to-End Encryption.
### Real-Time Communication
 Communication between clients and server is implemented using Java TCP sockets.
### Graphical User Interface built with JavaFX
### Admin panel
  #### User kick system
Admins can disconnect users.
#### Password reset functionality
Admin can reset a user's password directly from the panel.
#### Session tracking
Admins can view a real-time log of login and logout events, allowing them to monitor when and which users connect and disconnect.
### Testing
Unit tests for:
* AES/RSA encryption and decryption,password hashing,registation and password reset.
* SQLite database: Stores user credentials (username, hashed password).
##  Getting Started
Clone the repository:
```bash
git clone https://github.com/Przemekbukala/Whispr
```
Navigate to the project directory.
```bash
cd Whispr
```
To build the project, open a terminal in the project's root directory and run the following command:
```bash
./gradlew build
```

After this command start the server in one terminal by the folllowing command: 
```bash
./gradlew runServer
```
Client in different terminals:
```bash
./gradlew run
```
To exit the chat simply press "Log Out" buttom.
If you want to use Admin panel run the following commands:
```bash
./gradlew setupAdmin
```
```bash
./gradlew runAdmin
```
### Example
[[Whispr App]](https://www.youtube.com/watch?v=5be4ttuj_hE&ab_channel=Przemys%C5%82awBuka%C5%82a)
