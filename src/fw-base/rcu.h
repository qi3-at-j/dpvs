#ifndef _RCU_H_
#define _RCU_H_


typedef struct tagRCU_REG_S RCU_REG_S;
typedef VOID (*RCU_CALLBACK_PF)(RCU_REG_S* pstRegData);
struct tagRCU_REG_S
{
    struct tagRCU_REG_S *stNode;
    RCU_CALLBACK_PF pfCallback;
};

#endif