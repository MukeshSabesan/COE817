For Lab 3:

1. Navigate to the src directory.
2. Open a command line terminal in the directory.
3. Compile the KDC, Client A and Client B files by running the following command in the src directory:

javac KDC_Server.java Client_A.java Client_B.java

4. Then run the KDC Server file first using the command below in the src directory, as it has to listen and accept the Clients socket:

java KDC_Server

5. Create a new terminal in the same directory and run the Client A or B file using the command below:

"java Client_A" or "java Client_B"

6. This should start the program and show the step by step hybrid key distribution protocol process.