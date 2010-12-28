#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static FILE* katFile;
static const char INDENT[] =  "    ";

typedef struct KatResult {
    int stateSize;
    int hashBitLength;
    int msgLength;
    uint8_t* msg;
    int msgFill;
    uint8_t* result;
    int resultFill;
    int macKeyLen;
    uint8_t* macKey;
    int macKeyFill;
    char* restOfLine;
} KatResult_t;

#define Start 0
#define Message 1
#define Result 2
#define MacKeyHeader 3
#define MacKey 4
#define Done 5

static int state;

static void Show08(size_t cnt, const uint8_t* b)
{
    size_t i;
    for (i=0;i < cnt;i++)
    {
        if (i %16 ==  0) printf(INDENT);
        else if (i % 4 == 0) printf(" ");
        printf(" %02X",b[i]);
        if (i %16 == 15 || i==cnt-1) printf("\n");
        fflush(stdout);
    }
}


void openKatFile(const char* name)
{
    katFile = fopen(name, "r");
    if (katFile == NULL) {
        fprintf(stderr, "can't open kat file: %s, error: %d\n", name, errno);
        exit(1);
    }
}

static void parseHeaderLine(const char* pc, KatResult_t* kr)
{
    int ret;
    int consumed;

    ret = sscanf(pc, ":Skein-%d: %d-bit hash, msgLen = %d%n",
                 &kr->stateSize, &kr->hashBitLength, &kr->msgLength, &consumed);

    if ((kr->msgLength == 0) || (kr->msgLength % 8) != 0)
        kr->msg = (unsigned char*)malloc((kr->msgLength >> 3) + 1);
    else
        kr->msg = (unsigned char*)malloc(kr->msgLength >> 3);

    if ((kr->hashBitLength % 8) != 0)
        kr->result = (unsigned char*)malloc((kr->hashBitLength >> 3) + 1);
    else
        kr->result = (unsigned char*)malloc(kr->hashBitLength >> 3);

    kr->msgFill = 0;
    kr->resultFill = 0;
    kr->macKeyFill = 0;
}

static void parseMessageLine(const char*pc, KatResult_t* kr)
{
    int consumed = 0;
    unsigned int data;
    char* paren;
    int ret;
    int tmp;

    if ((paren = strchr(pc, '(')) != NULL) {
        if (strncmp(paren, "none", strlen("none")))
            return;
        fprintf(stderr, "Inconsistent message line: %s\n", pc);
        exit(1);
    }
    while ((ret = sscanf(pc+consumed, " %x%n", &data, &tmp)) > 0) {
        consumed += tmp;
        kr->msg[kr->msgFill++] = data;
    }
}

static void parseResultLine(const char*pc, KatResult_t* kr)
{
    int consumed = 0;
    unsigned int data;
    int ret;
    int tmp;

    while ((ret = sscanf(pc+consumed, " %x%n", &data, &tmp)) > 0) {
        consumed += tmp;
        kr->result[kr->resultFill++] = data;
    }
}

static void parseMacKeyLine(const char*pc, KatResult_t* kr)
{
    int consumed = 0;
    unsigned int data;
    char* paren;
    int ret;
    int tmp;

    if ((paren = strchr(pc, '(')) != NULL) {
        if (strncmp(paren, "none", strlen("none")))
            return;
        fprintf(stderr, "Inconsistent MAC key data line: %s\n", pc);
        exit(1);
    }
    while ((ret = sscanf(pc+consumed, " %x%n", &data, &tmp)) > 0) {
        consumed += tmp;
        kr->macKey[kr->macKeyFill++] = data;
    }
}

static void parseMacKeyHeaderLine(const char*pc, KatResult_t* kr)
{
    int ret;
    int consumed;

    ret = sscanf(pc, "MAC key = %d%n",
                 &kr->macKeyLen, &consumed);

    printf("ret: %d, macKeyLen %d, consumed: %d, rest: '%s'\n",
           ret, kr->macKeyLen, consumed, pc+consumed);

    kr->macKey = (unsigned char*)malloc(kr->macKeyLen);

    state = MacKey;
}

static void parseLine(const char* pc, KatResult_t* kr)
{

    if (strncmp(pc, "Message", strlen("Message")) == 0) {
        state = Message;
        return;
    }
    if (strncmp(pc, "Result", strlen("Result")) == 0 ) {
        state = Result;
        return;
    }
    if (strncmp(pc, "MAC", strlen("MAC")) == 0) {
        state = MacKeyHeader;
    }
    if (strncmp(pc, "------", strlen("------")) == 0) {
        state = Done;
        return;
    }

    switch (state) {
    case Start:
        if (strncmp(pc, ":Skein-", strlen(":Skein-")) == 0) {
            parseHeaderLine(pc, kr);
        }
        else {
            fprintf(stderr, "Wrong format found: %s", pc);
            exit(1);
        }
        break;
    case Message:
        parseMessageLine(pc, kr);
        break;
    case Result:
        parseResultLine(pc, kr);
        break;
    case MacKey:
        parseMacKeyLine(pc, kr);
        break;
    case MacKeyHeader:
        parseMacKeyHeaderLine(pc, kr);
        break;
    }
}


/**
 * Fill in data from KAT file, one complete element at a time.
 *
 * @param kr The resulting KAT data
 * @return
 */
int fillResult(KatResult_t* kr) {

    int dataFound = 0;
    char inb[512];
    char* pc = inb;
    size_t len = 512;
    size_t ret;

    while (state != Done) {
        ret = getline(&pc, &len, katFile);
        if (ret <= 3)
            continue;
        if (ret == -1) {
            dataFound = 0;
            break;
        }
        parseLine(pc, kr);
        dataFound = 1;
    }
    state = Start;
    return dataFound;
}

#ifdef KAT_SCAN_TESTING
int main(int argc, char* argv[])
{
    KatResult_t res;

    state = Start;
    openKatFile("/home/werner/devhome/skein3fish.git/data/skein_golden_kat.txt");
    while (fillResult(&res)) {
        printf("mac key filled: %d\n", res.macKeyFill);
        Show08(res.macKeyFill, res.macKey);
        
        printf("msg filled: %d\n", res.msgFill);
        Show08(res.msgFill, res.msg);
        
        printf("res filled: %d\n", res.resultFill);
        Show08(res.resultFill, res.result);
    }
    return 0;
}
#endif