#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 1024

int main() {
    int key;
    char input[BUFFER_SIZE];
    char output[BUFFER_SIZE];

    printf("Enter the Key: ");
    scanf("%d", &key);
    printf("Enter the Text (plain in lower and Cipher in upper): ");
    scanf("%s", input);

    int len = strlen(input);
    int i = 0;
    output[len] = '\0'; 

    if (input[0] >= 'a' && input[0] <= 'z') {
        while (input[i] != '\0') {
            output[i] = (((int)input[i] - (int)'a' + key) % 26) + 'A'; 
            i++;
        }
        printf("The Cipher text: %s\n", output); 
    } else {  
        while (input[i] != '\0') {
            output[i] = (((int)input[i] - (int)'A' + key) % 26) + 'a'; 
            i++;
        }
        printf("The Plain text: %s\n", output);  
    }

    return 0;
}
