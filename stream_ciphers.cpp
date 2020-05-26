#include <iostream>
#include <cmath>

char *encode( char *plaintext, unsigned long key );
char *decode(char *cipher_text, unsigned long key );

char *decode(char *cipher_text, unsigned long key ){
    unsigned int i{0},j{0},size{0},r{0},modulo{0},new_size{0};
    unsigned char state[256]{},swap{};
    
    //This determines the the size of the ciphertext array
    while (cipher_text[size]!='\0'){
        size++;
    }
    new_size = 4*((size)/5)+1;
    
    //This is the output array and the last value is filled with the null character
    char *plain_text = new char[new_size];
    plain_text[new_size-1]= '\0';
    
    //This arrays will be used to store the characters until they get xor
    unsigned char temp_array[size];
    
    //This loop undoes the ascii armor
    for (int n{0};n<(size/5);n++){
        modulo = 0;
        for (int x{0};x<5;x++){
            modulo += ((cipher_text[5*n+x]) - '!')*pow(85,4-x);
        }
        for (int x{0};x<4;x++){
            temp_array[(4*n)+x] = modulo>>((3-x)*8);
        }
    }
    
    //These loops are to intiailize the state array based on the given key
    for (int n{0};n<256;n++){
        state[n]=n;
    }
    for (int n{0};n<256;n++){
        unsigned int k{i%64};
        j = (j +state[i]+((key & (1UL<<k)) >> k))%256;
        swap = state[i];
        state[i]= state[j];
        state[j] = swap;
        i=(i+1)%256;
    }

    //This reverts the ciphertext to the plaintext
    for (int n{0};n<new_size-1;n++){
        i=((i+1) % 256);
        j = (j + state[i])%256;
        swap = state[i];
        state[i]= state[j];
        state[j] = swap;
        r = (state[i]+state[j])%256;
        plain_text[n] = temp_array[n]^state[r];
    }

    return plain_text;
}

char *encode (char *plaintext, unsigned long key){
    
    unsigned int i{0},j{0},size{0},r{0},diff{0},new_size{0},modulo{0},quotient{0};
    unsigned char state[256]{},swap{};
    
    //This determines the the size of the plaintext array - 1
    while (plaintext[size]!='\0'){
        size++;
    }
    
    //This determine how many null characters need to be added later
    while ((diff+size)%4!=0){
        diff++;
    }
    
    //This arrays will be used to store the xor characters before they become readable
    unsigned char temp_array[diff+size];
    
    //These loops are to intiailize the state array based on the given key
    for (int n{0};n<256;n++){
        state[n]=n;
    }
    for (int n{0};n<256;n++){
        unsigned int k{i%64};
        j = (j +state[i]+((key & (1UL<<k)) >> k))%256;
        swap = state[i];
        state[i]= state[j];
        state[j] = swap;
        i=(i+1)%256;
    }
    
    //This fills the temp_array which will be turned into readable characters
    for (int n{0};n<size;n++){
        i=((i+1) % 256);
        j = (j + state[i])%256;
        swap = state[i];
        state[i]= state[j];
        state[j] = swap;
        r = (state[i]+state[j])%256;
        temp_array[n] = plaintext[n]^state[r];
    }
    
    //This adds the encrypted null characters to the array
    for (int n{0};n<diff;n++){
        i=((i+1) % 256);
        j = (j + state[i])%256;
        swap = state[i];
        state[i]= state[j];
        state[j] = swap;
        r = (state[i]+state[j])%256;
        temp_array[size+n] = '\0'^state[r];
    }
    
    //These calculations determine the size of the output array
    unsigned int limit{(diff+size)/4};
    new_size = 5*(limit)+1;
    
    //This is the output array and the last value is filled with the null character
    char *cipher_text = new char[new_size];
    cipher_text [new_size - 1] = '\0';
    
    //Ascii armour
    for(int n{0};n<limit;n++){
        modulo = 0;
        for (int x{0};x<4;x++){
            modulo += (temp_array[(4*n)+x]<<(8*(3-x)));
        }
        modulo %= 85;
        
        for (int x{0};x<4;x++){
            quotient += (temp_array[(4*n)+x]<<(8*(3-x)));
        }
        quotient /= 85;
        for (int x{4};x>=0;x--){
            cipher_text[5*n+x] = modulo +'!';
            modulo = quotient%85;
            quotient = std::floor(quotient/85);
        }
    }
    
    
    return cipher_text;
}

#ifndef MARMOSET_TESTING
int main();
#endif

#ifndef MARMOSET_TESTING
int main() {
    char str0[]{ "Hello world!" };
    char str1[]{ "A Elbereth Gilthoniel\nsilivren penna miriel\n""o menel aglar elenath!\nNa-chaered palan-diriel\n""o galadhremmin ennorath,\nFanuilos, le linnathon\n""nef aear, si nef aearon!" };// [1]
    std::cout << "\"" << str0 << "\"" << std::endl;

    char *ciphertext{ encode( str0, 51323 ) };
    std::cout<< "\"" << ciphertext << "\"" << std::endl;
    char *plaintext{ decode( ciphertext, 51323 ) };std::cout << "\"" << plaintext << "\"" << std::endl;

    delete[] plaintext;
    plaintext= nullptr;
    delete[] ciphertext;
    ciphertext= nullptr;
    
    std::cout << "\"" << str1<< "\"" << std::endl;
    ciphertext = encode( str1, 51323 );
    std::cout << "\"" << ciphertext << "\"" << std::endl;
    plaintext = decode( ciphertext, 51323 );
    std::cout << "\"" << plaintext << "\"" << std::endl;
    delete[] plaintext;plaintext= nullptr;
    delete[] ciphertext;
    ciphertext= nullptr;
    
    return 0;
}
#endif

