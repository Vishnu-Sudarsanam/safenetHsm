#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>
#include <csa8fm.h>
#include <endyn.h>
#include <fmerr.h>
#include <md.h>

#define BUFF_SIZE    128
#define RESERVED     0
#define MY_FM_NUMBER 0x600

MD_RV Call_Fm(uint8_t *, uint32_t *);

int main()
{
    MD_RV rv = MDR_UNSUCCESSFUL;

    uint8_t  outBuf[BUFF_SIZE];
    uint32_t outLen = BUFF_SIZE;

    int i = 0;

    /** Initialize the message dispatch library */
    rv = MD_Initialize();
    if (rv != MDR_OK) {
        printf("MD_Initialize %x\n", rv);
        exit(1);
    }

    rv = Call_Fm(outBuf, &outLen);

    if (rv != MDR_OK) {
        printf("Call_Fm failed with error code: 0x%x\n", rv);
        exit(1);
    }

    /** Finalize the library. */
    MD_Finalize();

    printf("Chaincode length: %d"
           "\n------ Chaincode -----------\n",
           outLen);
    for (i = 0; i < outLen; printf("%02x", (unsigned char)outBuf[i++]))
        ;
    printf("\n----------------------------\n");

    exit(0);
}

MD_RV Call_Fm(uint8_t *out, uint32_t *outLen)
{
    MD_Buffer_t request[1], reply[2];
    MD_RV       rv = MDR_UNSUCCESSFUL;

    uint32_t recvLen      = 0,
             appState     = 0,
             originatorID = 0;
    uint8_t adapter       = 0;

    request[0].pData  = NULL;
    request[0].length = 0;

    reply[0].pData  = out;
    reply[0].length = *outLen;

    reply[1].pData  = NULL;
    reply[1].length = 0;

    rv = MD_SendReceive(adapter,
                        originatorID,
                        MY_FM_NUMBER,
                        request,
                        RESERVED,
                        reply,
                        &recvLen,
                        &appState);

    if (rv != MDR_OK) {
        *outLen = 0;
    } else {
        *outLen = (unsigned int)recvLen;
    }

    return (MD_RV)appState;
}
