/*
Copyright (c) 2010 Werner Dittmann

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

*/

#include <skeinApi.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "katscanner.h"

static const char INDENT[] =  "    ";  /* how much to indent on new line */
static void Show08(size_t cnt,const u08b_t *b)
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

static int notProcessed = 0;

static int processed = 0;


static int checkKATVectors() {
    KatResult_t kr;
    SkeinCtx_t ctx;
    uint8_t result[4000];
    char* paren;

    while (fillResult(&kr)) {
        /* Skip Tree vectors in this test function */
        if ((paren = strchr(kr.restOfLine, 'T')) != NULL && !strncmp(++paren, "ree", strlen("ree"))) {
            notProcessed++;
            freeResult(&kr);
            continue;
        }

        /* Check for MAC test vector */
        if ((paren = strchr(kr.restOfLine, 'M')) != NULL && !strncmp(++paren, "AC", strlen("AC"))) {

            skeinCtxPrepare(&ctx, kr.stateSize);
            skeinMacInit(&ctx, kr.macKey, kr.macKeyLen, kr.hashBitLength);

            skeinUpdateBits(&ctx, kr.msg, kr.msgLength);
            skeinFinal(&ctx, result);

            if (memcmp(result, kr.result, kr.resultFill)) {
                printf("%d-%d-%d-%s\n", kr.stateSize, kr.hashBitLength, kr.msgLength, kr.restOfLine);
                printf("Computed mac\n");
                Show08(kr.resultFill, result);
                printf("Expected result\n");
                Show08(kr.resultFill, kr.result);
                return 0;
            }
            processed++;
            freeResult(&kr);
            continue;
        }

        /* Check normal Skein vectors */
        skeinCtxPrepare(&ctx, kr.stateSize);
        skeinInit(&ctx, kr.hashBitLength);
        
        skeinUpdateBits(&ctx, kr.msg, kr.msgLength);
        skeinFinal(&ctx, result);

        if (memcmp(result, kr.result, kr.resultFill)) {
            printf("%d-%d-%d-%s\n", kr.stateSize, kr.hashBitLength, kr.msgLength, kr.restOfLine);
            printf("Computed mac\n");
            Show08(kr.resultFill, result);
            printf("Expected result\n");
            Show08(kr.resultFill, kr.result);
            return 0;
        }
        freeResult(&kr);
        processed++;
    }
    return 1;
}

int main(int argc, char* argv[])
{
    openKatFile("/home/werner/devhome/skein3fish.git/data/skein_golden_kat.txt");

    if (checkKATVectors())
        return 0;
    else
        return 1;
}
