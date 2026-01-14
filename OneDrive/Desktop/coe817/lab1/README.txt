For Project 1:
To run either the SiriServer and/or SiriClient perform the following:
1. Navigate to the src directory in project-1 folder.
2. Open a command line terminal in the directory.
3. Compile the protocol, server and client .java files by running the following command:

javac project\pkg1\SiriServer.java project\pkg1\SiriProtocol.java project\pkg1\SiriClient.java

4. Once that is finished, you can run the SiriServer from the current terminal with the following command:

java project.pkg1.SiriServer <portnumber>

The port number can be any number you choose (i.e: 4444)

5. Create a new terminal (follow steps 1 and 2) and run the SiriClient using the following command:

java project.pkg1.SiriClient localhost <portnumber> or java project.pkg1.SiriClient 127.0.0.1 <portnumber>

6. After this, you can ask any question you want from the client to the server, and the server should be able to respond.

7. To quit the connection from the client side, simply enter "quit" (ignore case) in the command line.