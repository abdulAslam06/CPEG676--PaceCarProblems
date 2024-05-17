#include <stdio.h>

int main(){

    // Initializing a Char array to store the final flag obtained
    char flag[35];

    // Given values array
    int values[28] = {110, 1, 105, 110, 1, 106, 2, 97, 123, 100, 3, 117, 53, 5, 116, 95, 48, 102, 8, 102, 95, 121, 48, 117, 114, 95, 67, 125};

    // Initializing index for storing the final flag
    int index = 0;

    // Looping through the values array
    for(int i=0; i<28; i++){

        // Condition to skip the values less than or equal to the value of 10
        if(values[i] <= 10){
            continue;
        }

        // Getting the ASCII equivalent of the given values and apppending it to the flag character array
        flag[index] = values[i];
        index++;
    }

    // Printing the Final flag
    printf("%s", flag);

}