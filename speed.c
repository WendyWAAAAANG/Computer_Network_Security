#include "aes.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>


typedef struct{
	uint8_t* data;
	int len;
	uint8_t* key;
} MY_ARGS;


void *task(void *args) {
	//clock_t start, end;
	//printf("task start time: %lf\n", (double)start/ CLOCKS_PER_SEC);
	MY_ARGS* my_args = (MY_ARGS*) args;
	uint8_t* data = my_args -> data;
	int len = my_args -> len;
	uint8_t* key = my_args -> key;
	aes_encrypt_ecb(AES_CYPHER_128, data, len, key);
	//end = clock();
	//printf("task running time: %lf\n", (double)(end - start) / CLOCKS_PER_SEC);
	return NULL;
}

void *task2(void *args) {
	//clock_t start, end;
	//printf("task start time: %lf\n", (double)start/ CLOCKS_PER_SEC);
	MY_ARGS* my_args = (MY_ARGS*) args;
	uint8_t* data = my_args -> data;
	int len = my_args -> len;
	uint8_t* key = my_args -> key;
	//start = clock();
	aes_decrypt_ecb(AES_CYPHER_128, data, len, key);
	//end = clock();
	//printf("task running time: %lf\n", (double)(end - start) / CLOCKS_PER_SEC);
	return NULL;
}

int main(){
	// Speed test for AES-128
	// input from text.
	printf("------Text IO------\n");
	clock_t start, end;
	double sum = 0, sum1 = 0;
	const int count =100000;
	uint8_t buf[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t iv[] = {0x60, 0xef, 0x17, 0x10, 0xd7, 0xcc, 0x28, 0xf8,
					0x56, 0xbd, 0xe4, 0x8b, 0xa1, 0xce, 0xb0, 0x87};// temp iv
	uint8_t data[sizeof(buf) * count];
	for(int i = 0; i < count; i++) {
		for(int j = 0; j < sizeof(buf); j++){
			data[i * sizeof(buf) + j] = buf[j];
		}
	}

    printf("Multi-thread implementation of ECB\n");
    //uint8_t data1[sizeof(data)/2];
	//uint8_t data2[sizeof(data)/2];
	uint8_t *data1 = (uint8_t*)malloc((sizeof(data)/2)*sizeof(uint8_t));
	uint8_t *data2 = (uint8_t*)malloc((sizeof(data)/2)*sizeof(uint8_t));
	
	for(int i = 0; i < sizeof(data)/2; i++) {
		data1[i] = data[i];
		data2[i] = data[i+sizeof(data)/2];
	}

	//thread
	pthread_t th1;
	pthread_t th2;
	pthread_t th3;
	pthread_t th4;
	MY_ARGS args1 = {data1, sizeof(data)/2, key};
	MY_ARGS args2 = {data2, sizeof(data)/2, key};

	start = clock();
	pthread_create(&th1, NULL, task, &args1);
	pthread_create(&th2, NULL, task, &args2);

	pthread_join(th1, NULL);
	pthread_join(th2, NULL);

	end = clock();
	double time1 = end-start;
	for(int i = 0; i < sizeof(data)/2; i++) {
		data[i] = data1[i];
		data[i+sizeof(data)/2] = data2[i];
	}
	printf("aes_encrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), time1 / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);


	start = clock();
	pthread_create(&th3, NULL, task2, &args1);
	pthread_create(&th4, NULL, task2, &args2);
	pthread_join(th3, NULL);
	pthread_join(th4, NULL);

	end = clock();
	double time2 = end-start;
	for(int i = 0; i < sizeof(data)/2; i++) {
		data[i] = data1[i];
		data[i+sizeof(data)/2] = data2[i];
	}
    	printf("aes_decrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), time2 / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);
	free(data1);
	free(data2);

	start = clock();
	aes_encrypt_ecb(AES_CYPHER_128, data, sizeof(data), key);
	end = clock();
	printf("aes_encrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);
	start = clock();
	aes_decrypt_ecb(AES_CYPHER_128, data, sizeof(data), key);
	end = clock();
	printf("aes_decrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

    printf("End of Multi-thread\n");

    printf("Start 5 normal implementation\n");

	start = clock();
	aes_encrypt_ecb(AES_CYPHER_128, data, sizeof(data), key);
	end = clock();
	printf("aes_encrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);

	start = clock();
	aes_decrypt_ecb(AES_CYPHER_128, data, sizeof(data), key);
	end = clock();
	printf("aes_decrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	start = clock();
	aes_encrypt_cbc(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_encrypt_cbc_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);

	start = clock();
	aes_decrypt_cbc(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_decrypt_cbc_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	//CTR_encryption
	start = clock();
	aes_xcrypt_ctr(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_encrypt_ctr_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);

	//CTR_decrption
	start = clock();
	aes_xcrypt_ctr(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_decrypt_ctr_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	//CFB_encryption
	start = clock();
	aes_xcrypt_cfb(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_encrypt_cfb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);

	//CFB_decrption
	start = clock();
	aes_xcrypt_cfb(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_decrypt_cfb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	//OFB_encryption
	start = clock();
	aes_xcrypt_ofb(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_encrypt_ofb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", data, 32);

	//OFB_decrption
	start = clock();
	aes_xcrypt_ofb(AES_CYPHER_128, data, sizeof(data), key, iv);
	end = clock();
	printf("aes_decrypt_ofb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);
	


	// input from file.
	printf("----File IO impelmentation----\n");
	// initialize sum and sum1.
    sum = 0;
	sum1 = 0;
        
    // open the file which store plaintext.
    // set the pointers points to file.
    FILE *fp_sum;
    // open file.
    fp_sum = fopen("buf.txt", "r");
    // check whether the file is available.
    if(fp_sum == NULL)
        printf("File does not exist");
            
    int i = 0, j;
    uint8_t x;
    char store[1000];
    fread(store, 1, 1000, fp_sum);
    fclose(fp_sum);

    // calculate length of store.
    int len = (int)strlen(store);
    //len_count=16
    int len_count = len/6 + 1;
        
    // open the file which store plaintext.
    FILE *fp1;
    // open the file.
    fp1 = fopen("buf.txt", "r");
    // check whether the file is available.
    if(fp1 == NULL)
        printf("File does not exist");
    int i1 = 0, j1;
    uint8_t x1;
    char store1[1000];
    fread(store1, 1, 1000, fp1);
    fclose(fp1);
        
    // open the file which store key.
    FILE *fp2;
    // open the file.
    fp2 = fopen("key.txt", "r");
    // check whether the file is available.
    if(fp2 == NULL)
        printf("File does not exist");
    int i2 = 0, j2;
    uint8_t x2;
    char store2[1000];
    fread(store2,1,1000,fp2);
    fclose(fp2);
    
    // open the file which store initial vector.
    FILE *fp3;
    // open the file.
    fp3 = fopen("iv.txt", "r");
    // check whether the file is available.
    if(fp3 == NULL)
        printf("File does not exist");
    int i3 = 0, j3;
    uint8_t x3;
    char store3[1000];
    fread(store3,1,1000,fp3);
    fclose(fp3);
        
    //store1是从txt中读出来的16进制数(buf).
    int len1 = (int)strlen(store1);
    //char类型数组，将从txt中读的写入a1中.
    char a1[len1];
    //将store1拷贝到a1中.
    strcpy(a1,store1);

    char tmpHex1[7];
    int num1;
    int counter1 = 0;

    for(int i=0;i<sizeof(a1)-1;i+=6){
        //tepHex1 -- hexidecimal, num -- decimal.
        strncpy(tmpHex1,a1+i,6);
        tmpHex1[6]='\0';
        sscanf(tmpHex1,"%x",&num1);
        sscanf(tmpHex1, "%hhx", &buf[counter1]);
        counter1++;
    }
    //store2是从txt中读出来的16进制数(key).
    int len2 = (int)strlen(store2);
    char a2[len2];
    strcpy(a2,store2);
    char tmpHex2[7];
    int num2;
    int counter2 = 0;
    for(int i=0;i<sizeof(a2)-1;i+=6){
        strncpy(tmpHex2,a2+i,6);
        tmpHex2[6]='\0';
        sscanf(tmpHex2,"%x",&num2);
        sscanf(tmpHex2, "%hhx", &key[counter2]);
        counter2++;
    }
       
    //store3是从txt中读出来的16进制数(iv).
    int len3 = (int)strlen(store3);
    char a3[len3];
    strcpy(a3,store3);
    char tmpHex3[7];
    int num3;
    int counter3 = 0;
    for(int i=0;i<sizeof(a3)-1;i+=6){
        strncpy(tmpHex3,a3+i,6);
        tmpHex3[6]='\0';
        sscanf(tmpHex3,"%x",&num3);
        sscanf(tmpHex3, "%hhx", &iv[counter3]);
        counter3++;
    }
    // le = 16.
    long unsigned le = (long unsigned)(len1/6+1);
    for(int i=0;i<count;i++) {
        for(int j=0;j<sizeof(buf);j++) {
            data[i*sizeof(buf)+j]=buf[j];
        }
    }
    start=clock();
    // store cipher into 'ciphertext.txt'.
    aes_encrypt_ecb(AES_CYPHER_128, data, (int)sizeof(data), key);
    end=clock();
    printf("aes_encrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
    aes_dump("cipher", data, 32);                               
    start = clock();
    aes_decrypt_ecb(AES_CYPHER_128, data, (int)sizeof(data), key);
    end = clock();
    printf("aes_decrypt_ecb_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
    aes_dump("plain", data, 32);
        
    start = clock();
    // store cipher into 'ciphertext.txt'.
    aes_encrypt_cbc(AES_CYPHER_128, data, (int)sizeof(data), key, iv);
    end = clock();
    printf("aes_encrypt_cbc_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
    aes_dump("cipher", data, 32);                                

    start = clock();
    aes_decrypt_cbc(AES_CYPHER_128, data, (int)sizeof(data), key, iv);
    end = clock();
    printf("aes_decrypt_cbc_128 %ld bytes time(s): %lf\n", sizeof(data), (double)(end - start) / CLOCKS_PER_SEC);
    aes_dump("plain", data, 32);
    printf("Read file finish!\n");
    return 0;

	return 0;
}