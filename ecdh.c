#include <stdio.h>
#include <sodium.h>

void print_hex(unsigned char *number, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x", number[i]);
    }
    printf("\n");
}

int main() {
    // init sodium
    if (sodium_init() < 0) {
        printf("Error init\n");
        return 1;
    }

    /* Alice key pair */
    unsigned char alice_pk[crypto_box_PUBLICKEYBYTES]; // public (A)
    unsigned char alice_sk[crypto_box_SECRETKEYBYTES]; // private (a)
    crypto_box_keypair(alice_pk, alice_sk);

    printf("Alice:\n");
    printf("public key (A): ");
    print_hex(alice_pk, crypto_box_PUBLICKEYBYTES);
    printf("private key (a): ");
    print_hex(alice_sk, crypto_box_SECRETKEYBYTES);

    /* Bob key pair */
    unsigned char bob_pk[crypto_box_PUBLICKEYBYTES]; // public (B)
    unsigned char bob_sk[crypto_box_SECRETKEYBYTES]; // private (b)
    crypto_box_keypair(bob_pk, bob_sk);

    printf("\nBob:\n");
    printf("public key (B): ");
    print_hex(bob_pk, crypto_box_PUBLICKEYBYTES);
    printf("private key (b): ");
    print_hex(bob_sk, crypto_box_SECRETKEYBYTES);

    unsigned char S_A[crypto_scalarmult_SCALARBYTES];
    unsigned char S_B[crypto_scalarmult_SCALARBYTES];

    /* Calculate shared secret for each side */
    if (crypto_scalarmult(S_A, alice_sk, bob_pk) != 0) {
        printf("Error\n");
    }
    if (crypto_scalarmult(S_B, bob_sk, alice_pk) != 0) {
        printf("Error\n");
    }

    printf("\nAlice's shared secret (S_A = a * B): \n");
    print_hex(S_A, crypto_scalarmult_SCALARBYTES);
    printf("Bob's shared secret (S_B = b * A): \n");
    print_hex(S_B, crypto_scalarmult_SCALARBYTES);

    if (crypto_verify_32(S_A, S_B) == 0) {
        printf("\nShared secrets are equal\n");
    } else {
        printf("\nShared secrets are NOT equal\n");
    }

    // aside (I quit)
    // printf("\nTheory verification (S_A = S_B = (a * b) * G):\n");
    // unsigned char S_ver[crypto_scalarmult_SCALARBYTES];
    // unsigned char temp[crypto_scalarmult_SCALARBYTES];
    // crypto_core_ed25519_scalar_add(temp, alice_sk, bob_sk);
    // if (crypto_scalarmult_base(S_ver, temp) != 0) {
    //     printf("Error\n");
    // }
    // printf("\nS_verify: \n");
    // print_hex(S_ver, crypto_scalarmult_SCALARBYTES);

    return 0;
}
