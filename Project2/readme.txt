We have followed the same steps which you mentioned in you myREADME.txt file.

steps to run the program:

1)Compile the code with the following command

g++ BigInt.cpp RSA.cpp main.cpp

2)Create the library with the following command

g++ -c BigInt.cpp RSA.cpp
ar rc libRSAutil.a BigInt.o RSA.o
ranlib libRSAutil.a

3)Use the library in the codewith the following command

g++ main.cpp -L. -l RSAutil -o prog   (that is an 'L' before RSAutil)

4)BigInt.h & RSA.h files must be in your current directory w/main.cpp & libRSAutil.a

5) Run the code with the following command

./prog