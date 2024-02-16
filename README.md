# java-webserver

A webserver, written in Java.  Uses the Postgres JDBC driver and CSS Bootstrap

## Features
 - File browsing with ability to upload/download files, renaming, deletion, folder creation, etc.
 - Access your server's shell from the web
 - Enter raw SQL commands into the database
 - Error handling with custom help messages

## Building

1. Modify `src/Main.java` and enter the details of your database (optional, but required if using database features)
2. (Optional) Modify `src/Main.java` to setup HTTPS, set the port number, etc. (The server runs plain HTTP by default on port 8080)
3. Build the jar file:
   ```shell
   ./build.sh
   ```
4. (Optional) Transfer the fully portable `webserver.jar` file to the desired server

## Running

1. Run the executable jar file:
   ```shell
   java -jar webserver.jar
   ```
2. In your web browser, navigate to `http://`_IP address with port_`/`
