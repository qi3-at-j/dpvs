#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "error.h"
#include "secbasetype.h"
//#include "../fw-base/in.h"
#include "secpolicy_common.h"
#include "secpolicy.h"


SECPOLICY_ALL_S g_stSecPolicyAll[SECPOLICY_TYPE_MAX];
SECPOLICY_ALL_S *g_pstSecPolicyExtFW = &g_stSecPolicyAll[SECPOLICY_TYPE_EXTBODER];
SECPOLICY_ALL_S *g_pstSecPolicyVPCFW = &g_stSecPolicyAll[SECPOLICY_TYPE_VPCBODER];
SL_HEAD_S * g_pstSecExtFlowHead = NULL;
SL_HEAD_S * g_pstSecVPCFlowHead = NULL;
SL_HEAD_S * g_pstExtSecConfHeadIP4 = NULL;
SL_HEAD_S * g_pstExtSecConfHeadIP6 = NULL;
SL_HEAD_S * g_pstVPCSecConfHeadIP4 = NULL;
SL_HEAD_S * g_pstVPCSecConfHeadIP6 = NULL;

VOID SecPolicy_Init(void)
{
    UINT uiIndex;
    SECPOLICY_ALL_S * pstSecPolicyCfg;
    for (uiIndex = SECPOLICY_TYPE_EXTBODER; uiIndex < SECPOLICY_TYPE_MAX; uiIndex++)
    {
        memset(&g_stSecPolicyAll[uiIndex], 0, sizeof(SECPOLICY_ALL_S));
        pstSecPolicyCfg = &g_stSecPolicyAll[uiIndex];
        SL_Init(&pstSecPolicyCfg->stSecFlow.stExtHead);
        SL_Init(&pstSecPolicyCfg->stSecConf.stHeadIP4);
        SL_Init(&pstSecPolicyCfg->stSecConf.stHeadIP6);
    }

    g_pstSecExtFlowHead = &g_pstSecPolicyExtFW->stSecFlow.stExtHead;
    g_pstSecVPCFlowHead = &g_pstSecPolicyExtFW->stSecFlow.stVPCHead;
    g_pstExtSecConfHeadIP4 = &g_pstSecPolicyExtFW->stSecConf.stHeadIP4;
    g_pstExtSecConfHeadIP6 = &g_pstSecPolicyExtFW->stSecConf.stHeadIP6;
    g_pstVPCSecConfHeadIP4 = &g_pstSecPolicyVPCFW->stSecConf.stHeadIP4;
    g_pstVPCSecConfHeadIP6 = &g_pstSecPolicyVPCFW->stSecConf.stHeadIP6;
    return;
}

VOID SecPolicy_Fini(void)
{
    SecPolicy_ExtFlow_DelAllTenantID();
    SecPolicy_Conf_DelAllTenantID();
    SecPolicy_Conf_DelAllVxlanID();
    return;
}
