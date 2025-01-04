#include <stdio.h>
#include <string.h>
#include <ctype.h>
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

    for (i = 0; i < len; i++) {
        if (islower(input[i])) {  // Encrypt lowercase to uppercase
            output[i] = (((input[i] - 'a') + key) % 26) + 'A';
        } else if (isupper(input[i])) {  // Decrypt uppercase to lowercase
            output[i] = (((input[i] - 'A') + key) % 26) + 'a';
        } else {  // Invalid character in input
            printf("Invalid character in input: %c\n", input[i]);
            return 1;
        }
    }

    output[len] = '\0';  // Null-terminate the output string

    if (islower(input[0])) {
        printf("The Cipher text: %s\n", output);
    } else {
        printf("The Plain text: %s\n", output);
    }

    return 0;
}
