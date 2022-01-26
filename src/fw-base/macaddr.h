#ifndef _MACADDR_H_
#define _MACADDR_H_

#define MAC_STRING_SIZE 15UL   /*MAC字符串长度,配合MAC_ToString使用*/

/*将Mac地址转换为字符串(转换后的格式为:xxxx-xxxx-xxxx)*/
/*pucMacAddr长度为MAC_ADDR_LEN,size推荐使用MAC_STRING_SIZE,pcString长度推荐使用MAC_STRING_SIZE*/
static inline VOID MAC_ToString(IN const UCHAR *pucMacAddr, IN size_t size, OUT CHAR *pcString)
{
    (VOID)snprintf(pcString,
                   size,
                   "%02x%02x-%02x%02x-%02x%02x",
                   pucMacAddr[0], 
                   pucMacAddr[1],
                   pucMacAddr[2],
                   pucMacAddr[3],
                   pucMacAddr[4],
                   pucMacAddr[5]);

    return;
}

#endif