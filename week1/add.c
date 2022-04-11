#include <stdio.h>
#include <stdint.h>
#include "ch.h"


int main(int argc,char *argv[]){
	FILE *fp, *fp1;
	uint32_t ac,bc,a,b;

	fp = fopen(argv[1],"r");
	if(fp==NULL)return -1;

	fp1 = fopen(argv[2],"r");
	if(fp1 == NULL) return -1;


	ac = fread(&a,sizeof(uint32_t),1,fp);
	bc = fread(&b,sizeof(uint32_t),1,fp1);
	printf("[*]checking\t%s : %x\n",argv[1],a);
	printf("[*]checking\t%s : %x\n",argv[2],b);

	fclose(fp);
	fclose(fp1);

	a=lobi8(a);
	b=lobi8(b);

	printf("%d(0x%x) + %d(0x%x)= %d(0x%x)",a,a,b,b,a+b,a+b);
	return 0;
}	
