#ifndef _SECPOLICY_H_
#define _SECPOLICY_H_

#ifdef __cplusplus
extern "C"{
#endif

extern VOID SecPolicy_SetFwType(SECPOLICY_TYPE_E enFwType);
extern SECPOLICY_TYPE_E  SecPolicy_GetFwType(VOID);
extern ULONG SecPolicy_ExtFlow_AddPubIP(IN UCHAR *pucTenantID, IN IP_ADDR_S *pstIPAddr);
extern VOID  SecPolicy_ExtFlow_DelPubIP(IN UCHAR *pucTenantID, IN IP_ADDR_S *pstIPAddr);
extern VOID  SecPolicy_ExtFlow_DelTenantID(IN UCHAR *pucTenantID);
extern VOID  SecPolicy_ExtFlow_DelAllTenantID();
extern ULONG SecPolicy_Conf_AddRule(IN SECPOLICY_RULE_CFG_S *pstRuleCfg);
extern ULONG SecPolicy_Conf_DelRule(IN SECPOLICY_RULE_CFG_S *pstRuleCfg);
extern ULONG SecPolicy_Conf_MoveRule(IN SECPOLICY_MOVE_RULE_S *pstRuleCfg);
extern VOID SecPolicy_Conf_DelTenantID(IN UCHAR *pucTenantID);
extern VOID SecPolicy_Conf_DelAllTenantID(VOID);
extern VOID SecPolicy_Conf_DelVxlanID(IN UINT uiVxlanID);
extern VOID SecPolicy_Conf_DelAllVxlanID(VOID);
extern ULONG SecPolicy_Conf_MdyRulePara(IN SECPOLICY_RULE_CFG_S *pstRuleCfg,
                                        IN BOOL_T bIsUndo);
extern VOID SecPolicy_VPCFlow_ShowVxlanID(IN UINT uiVxlanID, IN UINT uiIPType);
extern VOID SecPolicy_Conf_Show(IN SECPOLICY_RULE_CFG_S *pstRuleCfg);
extern VOID SecPolicy_Conf_SetDbg(IN UINT uiVxlanID, IN unsigned char *pucTenantID, IN UINT uiDbgType, IN BOOL_T bIsUndo, IN UINT uiIPType);
extern VOID SecPolciy_Conf_GetDbg(IN UINT uiVxlanID, IN unsigned char *pucTenantID, IN UINT uiIPType);
extern ULONG SecPolicy_Conf_AddVxlanID(IN UINT uiVxlanID, IN UINT uiIPType);
extern VOID SecPolicy_Conf_ClearStatistics(IN SECPOLICY_RULE_CFG_S *pstRuleCfg);
extern VOID SecPolicy_ExtFlow_ShowTenantID(IN unsigned char *pucTenantID, IN unsigned int uiIPType);

#ifdef __cplusplus
}
#endif

#endif
