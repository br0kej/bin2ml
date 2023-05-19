#include <stdio.h>
int main() {
   printf("This is a very silly program!");
   int zero = 0;

   if (zero != 1) {
        printf("Not one!");
   } else {
        printf("Hello, World!");
   }

   int not_zero = zero + 1;

   if (not_zero != 0) {
    printf("Not zero!");
   } else if (not_zero == 10){
    printf("Unreachable silly");
   } else {
    printf("Even more unreachable!");
   }
   
   return 0;
}