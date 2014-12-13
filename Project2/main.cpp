#include <string>
#include "RSA.h"
#include "BigInt.h"
#include "stdio.h"
#include <limits>
#include <iostream>
#include "time.h"
#include "stdlib.h"


#define LIMIT_RAND 0xFFFFFFF
using namespace RSAUtil;

void generate_prime(int *,int); // function to generate prime numbers
void generate_nonprime(int *,int); // function to generate non prime number
void converttoint(BigInt,unsigned long*,int); // function to convert bigint to int
BigInt sendtoAlice(BigInt,BigInt); //function to send public key and modN to alice
void sendtoAlice2(BigInt,BigInt,BigInt); // function to send decrypted message to alice

//global memory for sharing the message and the random number Alice generates
BigInt randomno,message;

int main(){
/* Implementation of task1*/

std::cout<<"\n\n************Task1***********"<<std::endl;
srand(time(NULL));
/* Subtask1 */
std::cout<<"\n************Subtask1************"<<std::endl;
RSA objRSA[10];
//char * messages[]={"One","Two","Three","Four","Five","Six","Seven","Eight","Nine","Ten"};
int msg=int(((double)rand()/RAND_MAX)*LIMIT_RAND);  //generation of random message
BigInt result(0);
for(int i=0;i<10;i++){
        printf("\nEncrypting the message %d \n", msg);
        result=objRSA[i].encrypt(msg);                //Encryption of message
        std::cout<<"Encryption result : "<<result.toHexString()<<std::endl;
}
/* Subtask 2 */
std::cout<<"\n***********Subtask2**************"<<std::endl;
RSA * objRSA_onearg[5]={NULL};
std::cout<<"\nEncrypting the message "<<msg<<std::endl;
int primep[10]={0};
generate_prime(primep,10);//prime number generation
for(int i=0;i<5;i++){
objRSA_onearg[i] = new RSA (primep[i]);
result = objRSA_onearg[i]->encrypt(msg); // encrypt message
std::cout<<"\nEncryption result using the prime p as "<<primep[i]<<" is "<<result.toHexString()<<std::endl;
result = objRSA_onearg[i]->decrypt(result);//decrypt message
std::cout<<"Decryption result : "<<result.toHexString()<<std::endl;
}

/* Subtask 3 */
std::cout<<"\n***********Subtask3**************"<<std::endl;
RSA * objRSA_twoarg[5]={NULL};
std::cout<<"\nEncrypting the message "<<msg<<std::endl;
for(int i=0;i<5;i++){
objRSA_onearg[i] = new RSA (primep[i],primep[5+i]);
result = objRSA_onearg[i]->encrypt(msg);//encrypting the message
std::cout<<"\nEncryption result using the prime p and q as  "<<primep[i]<<" "<<primep[5+i]<<" is "<<result.toHexString()<<std::endl;
result = objRSA_onearg[i]->decrypt(result);//decrypting the message
std::cout<<"Decryption result : " << result.toHexString()<<std::endl;
}
/* Subtask 4 */
std::cout<<"\n***********Subtask4**************"<<std::endl;
RSA * objRSA_twononprimearg[5]={NULL};
int nprime[10]={0};
generate_nonprime(nprime,10);//generate non prime numbers
std::cout<<"\nEncrypting the message "<<msg<<std::endl;
for(int i=0;i<5;i++){
objRSA_onearg[i] = new RSA (nprime[i],nprime[5+i]);
result = objRSA_onearg[i]->encrypt(msg);//encrypting the message
std::cout<<"\nEncryption result using the non prime p and q as  "<<nprime[i]<<" "<<nprime[5+i]<<" is "<<result.toHexString()<<std::endl;
result = objRSA_onearg[i]->decrypt(result);//decrypt message
std::cout<<"Decryption result : "<<result.toHexString()<<std::endl;
if(result==objRSA_onearg[i]->encrypt(msg)){//check if encrypted and decrypted messages are same
std::cout<<"This case is an out of ordinary case "<<std::endl;
}
}
/*Implementation of task3*/
/*********Task2********/
std::cout<<"\n\n***************Task2*********"<<std::endl;
RSA RSAObj1;
RSA RSAObj2;
unsigned long result_long[2];
int size_result_array=2;
result=RSAObj1.getPublicKey();
RSAObj2.setPublicKey(result);
RSAObj2.setN(RSAObj1.getModulus());
//int rno=rand();
BigInt rno=int(((double)rand()/RAND_MAX)*LIMIT_RAND);//random message 
 std::cout<<"\noriginal message="<<rno.toHexString()<<std::endl;
result=RSAObj2.encrypt(rno);
std::cout<<"encrypted message="<<result.toHexString()<<std::endl;
result=RSAObj1.decrypt(result);
std::cout<<"decrypted message="<<result.toHexString()<<std::endl;
//converttoint(result,result_long,size_result_array);
if(result==rno){//check if values match
 std::cout<<"Original message and decrypted messages match , hence verified "<<std::endl;
}

/*Implementation of task3*/
/************Task3********/
std::cout<<"\n\n*****************Task3***************"<<std::endl;

RSA Bobobj;
BigInt pk= Bobobj.getPublicKey();
BigInt mod= Bobobj.getModulus();
//Bob sends public key and modN to Alice
BigInt msgAlice=sendtoAlice(pk,mod);
//Bob decrypts the message received from Alice 
BigInt decmessage= Bobobj.decrypt(msgAlice);
//send the decrypted message to Alice again
sendtoAlice2(decmessage,pk,mod);
}

void sendtoAlice2(BigInt msg,BigInt pk,BigInt mod){
RSA verifyobj;//verification object
verifyobj.setN(mod);
verifyobj.setPublicKey(pk);
BigInt randomInv=modInverse(randomno,mod);
BigInt mulmsg=msg*randomInv;
std::cout<<"signedmessage="<<mulmsg.toHexString()<<std::endl;
BigInt signedmsg=mulmsg%mod;//the actual signature of the message
BigInt finalmessage=verifyobj.encrypt(signedmsg);
std::cout<<"finalmessage="<<finalmessage.toHexString()<<std::endl;
//check if matches with original message after decrypting 
if(finalmessage==message){
std::cout<<"Initial and final messages are matching , hence verified\n\n"<<std::endl;

}
}

BigInt sendtoAlice(BigInt pk,BigInt mod){
RSA Aliceobj;
Aliceobj.setN(mod);
Aliceobj.setPublicKey(pk);
randomno=int(((double)rand()/RAND_MAX)*LIMIT_RAND);//generate the random number
message=int(((double)rand()/RAND_MAX)*LIMIT_RAND);//generate the message
std::cout<<"\ninitialmessage="<<message.toHexString()<<std::endl;
BigInt encrandom=Aliceobj.encrypt(randomno);//encrypt the number in Bob's public key
BigInt mulmsg=encrandom*message;
mulmsg=mulmsg%mod;
return mulmsg;
}


void converttoint(BigInt result,unsigned  long * result_long,int size_result_array){
result.toULong(result_long,size_result_array);
}

void generate_prime(int *prime,int counter){
for(int i=60001, j=0;j<counter;i++){
if(isPrime(i)){
prime[j++]=i;
}
}
}
void generate_nonprime(int *prime,int counter){
for(int i=30001, j=0;j<counter;i++){
if(!isPrime(i)){
prime[j++]=i;
}
}
}