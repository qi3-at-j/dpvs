#ifndef _MACADDR_H_
#define _MACADDR_H_

#define MAC_STRING_SIZE 15UL   /*MAC�ַ�������,���MAC_ToStringʹ��*/

/*��Mac��ַת��Ϊ�ַ���(ת����ĸ�ʽΪ:xxxx-xxxx-xxxx)*/
/*pucMacAddr����ΪMAC_ADDR_LEN,size�Ƽ�ʹ��MAC_STRING_SIZE,pcString�����Ƽ�ʹ��MAC_STRING_SIZE*/
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