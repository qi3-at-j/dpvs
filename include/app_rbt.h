#ifndef _APP_RBT_H_
#define _APP_RBT_H_

#ifdef __cplusplus
extern "C"{
#endif

extern void App_Rbt_Fini(void);
extern int32_t App_Rbt_Init(void);
extern void App_Rbt_Process(void);

/*
* return 0:Invalid values
*/
extern unsigned int App_Rbt_GetAppIDBySubID(unsigned int uiSubID);


#ifdef __cplusplus
}
#endif

#endif

