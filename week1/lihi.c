#include <stdio.h>
#include <stdint.h>

uint32_t lobi8(uint32_t p){
	return p<<24 | p>>24| (p &0xff0000)>>8 |(p &0xff00)<<8;
}
