#ifdef BUILD_TODO


/*
epoll���Ⱥ���
**/
VOID SESSIOND_EPOLL_Wait(VOID)
{
	INT iFds;
	INT iNum;
	epoll_callback_t pfCallBack;
	struct epoll_event astEvent[SESSION_MAX_EPOLLEVENT];

	for (;;)
	{
		iFds = epoll_wait(g_iSessiondEpollFd, astEvent, SESSION_MAX_EPOLLEVENT, -1);
		for (iNum = 0; iNum < iFds; iNum++)
		{
			pfCallBack =(epol_callback_t)(ULONG)(astEvent[iNum].callback);
			if (NULL != pfCallBack)
			{
				(VOID)pfCallBack(astEvent[iNum].events, astEvent[iNum].data.ptr);
			}
		}
	}	
}


/*
Description:��ʼ��EPOLL
***/
ULONG SESSIOND_EPOLL_Init(VOID)

{
	ULONG ulErrCode = ERROR_FAILED;
	INT iEpfd;

	iEpfd = epoll_create(1);
	if (iEpfd >= 0)
	{
		g_iSessiondEpollFd = iEpfd;
		ulErrCode = ERROR_SUCCESS;
	}

	return ulErrCode;
}


/****
Description:��ȡEPollFd
****/
INT SESSION_EPOLL_GetEpollFd(VOID)
{
	return g_iSessiondEpollFd;
}

/***
Description:�յ�ָ���˳��ź�ʱ�Ĵ�����
*****/
static VOID _session_signal_handler(IN const struct signalfd_siginfo *pstSigInfo)
{
	INT iExitCode;

	switch (pstSigInfo->ssi_int)
	{
		case SERVICE_STOPTYPE_NORMAL:
		case SERVICE_STOPTYPE_UPGRADE:
		case SERVICE_STOPTYPE_REBOOT:
		{
			iExitCode= EXIT_SUCCESS;
			break;
		}
		case SERVICE_STOPTYPE_EXCEPT:
		{
			iExitCode= EXIT_FAILURE;
			break;
		}
		default:
		{
			iExitCode = EXIT_FAILURE;
			break;
		}
	}

	_session_exit();
	exit(iExitCode);
}

/********
   Func Name: _session_signal_callback_epoll
Date Created:
      Author:
 Description: �ź��¼��ص�����
       Input: UINT uiEvent�� Epoll�¼�
              VOID *pHandle��Epoll����
      Output: ��
      Return: ERROR_SUCCESS�� ����ɹ�
     Caution: ����EPOLLHUP��EPOLLERR�¼�˵��ϵͳ�Ѿ��������ˣ�
              ��˲���������¼���
*/
static ULONG _session_signal_callback_epoll(IN UINT uiEvent, IN VOID *pHandle)
{
	INT iFd;
	INT iLen;
	struct signalfd_siginfo stSiginfo;

	/* �Ӳ�������ȡclient��socket */
	iFd = (INT)(UINT)(ULONG)pHandle;

	if (0 != (EPOLLIN & uiEvent))
	{
		iLen = (INT)read(iFd, &stSiginfo, sizeof(struct signalfd_siginfo));

		if (iLen == (INT)(UINT)sizeof(struct signalfd_siginfo))
		{
			_session_signal_handler(&stSiginfo);
		}
		
	}

	return ERROR_SUCCESS;
}


/***
Description:�źŴ����ʼ��
***/
static ULONG _session_signal_init(VOID)
{
	ULONG ulErr;
	INT iSignalFd;
	INT iRet;
	sigset_t stMask;

	(VOID)sigemptyset(&stMask);

	/* ע����̽���ʵʱ�ź� */
	(VOID)sigaddset(&stMask, SIGNAL_SERVICE_SHUTDOWN);

	/* ���߳����θ��źţ�����ת��Ϊsignalfd���� */
	iRet = sigprocmask(SIG_BLOCK, &stMask, NULL);
	if (iRet<0)
	{
		return ERROR_FATLED;
	}

	/* ��ȡ���źŶ�Ӧ��FD */
	iSignalFd = signalfd(-1, &stMask, 0);
	if (iSignalFd < 0)
	{
		return ERROR_FAILED;
	}

	ulErr = SESSION_EPOLL_AddToEpoll(iSignalFd, _session_signal_callback_epoll);
	if (ERROR_SUCCESS != ulErr)
	{
		close(iSignalFd);
		return ERROR_FAILED;
	}

	g_iSignalFd = iSignalFd;

	return ERROR_SUCCESS;
}

/*************
Description�� �ػ����̹�����Դ��ʼ��
****/
static ULONG _session_init_pub(VOID)
{
	ULONG ulErr = ERROR_SUCCESS;

	ulErr = SESSIOND_EPOLL_Init();

	if (ERROR_SUCCESS == ulErr)
	{
		ulErr |= _session_signal_init();
	}
	
	return ulErr;
}


/***********
Description���ػ����̹�����Դȥ��ʼ��
*/
static VOID _session_exit_pub(VOID)
{
	_session_signal_exit();
	SESSIOND_EPOLL_Exit();

	return;
}

/* master-slot������ʼ�� */
ULONG SESSIOND_HA_MasterInit(VOID)
{
	ULONG ulErr = ERROR_SUCCESS;

	ulErr |= SESSIOND_IF_EventInit();
	ulErr |= SESSIOND_ZONEPAIR_EventInit();
	(VOID)SESSIOND_ACL_EventInit();
	ulErr |= SESSIOND_MDC_EventInit();

	SESSIOND_APPMNG_Regisger();
	ulErr |= SESSIOND_APPMNG_AllAppInit();

	if (ERROR_SUCCESS != ulErr)
	{
	    ulErr = ERROR_FAILED;
	}

	return ulErr;
}


/* mpu��̬�����ӿ� */
static ULONG _session_init_arch(VOID)
{
	ULONG ulErr = ERROR_SUCCESS;

	if (ERROR_SUCCESS != SESSIOND_HA_Init())
	{
		return ERROR_FAILED;
	}

	if (BOOL_TRUE == SESSION_HA_IsMaster())
	{
		ulErr = SESSIOND_HA_MasterInit()
		/* ��������slot��session���� */
		if (ERROR_SUCCESS == ulErr)
		{
			_session_startup_node_service();
		}
	}
	else
	{
		ulErr = SESSIOND_HA_SlaveInit();
	}

	return ulErr;
}

/* mpu��̬�˳��ӿ� */
static VOID _session_exit_arch(VOID)
{
	if (BOOL_TRUE == SESSION_HA_IsMaster())
	{
		SESSIOND_HA_MasterExit();
	}
	else
	{
		SESSIOND_HA_SlaveExit();
	}
	
	SESSIOND_HA_Exit();
    
	return;
}

/*
Description���ػ�������Դ��ʼ��
****/
static ULONG _session_init(VOID)
{
	ULONG ulErr;
	ULONG ulFSError; /* cpu_exception */
	CHAR szDefaultPath[128]; /* cpu_exception */
	ulErr = _session_init_pub(); 
	if (ERROR_SUCCESS == ulErr)
	{
		ulErr = _session_init_arch();
	}
	

	/* cpu_exception */
	if (MDC_OS_MMDC_ID == MDC_GetCurrentMDC())
	{
		szDefaultPath[0] = '\0';
		ulFSError = FS_GetLocalDefaultWorkDir(sizeof(szDefaultPath), szDefaultPath);
		if (ERROR_SUCCESS == ulFSError)
		{
			SESSION_ioctl_Send(SESSION_CTOCTL_EXCEPTION_INIT, strlen(szDefaultPath), szDefaultPath);
		}
	}

	return ulErr;
}


static VOID _session_exit(VOID)
{
	_session_exit_arch();
	_session_exit_pub();
	return;	
}


static ULONG _session_app_init(VOID)
{
	ULONG ulErr = ERROR_SUCCESS;
    
	if (BOOL_TRUE == SESSION_HA_IsMaster())
	{
		/* sessionģ����Դ��ʼ�� */
		SESSION_DBG_Init();
		SESSION_ApplicationInit();
		ulErr |= SESSION_MDC_Init();
		ulErr |= SESSION_IF_Init();
		ulErr |= SESSION_ACL_Init();
		ulErr |= SESSION_GCFG_Init();
		ulErr |= SESSION_IFCFG_Init();
		ulErr |= SESSION_DBM_Init();
		ulErr |= SESSION_GS_Init();
		ulErr |= SESSION_MESH_ServerInit();
		ulErr |= SESSION_ZONEPAIR_Init();
		HOTBACKUP_Enable(BOOL_TRUE);

		if (ERROR_SUCCESS == ulErr)
		{
			SESSION_RECOVER_Cfg();

			/* �Ƿ���Ҫ����topͳ���߳� */
			if (BOOL_TRUE == SESSION_GCFG_GetTopHisStatEnable())
			{
				ulErr |= Session_Top_ThreadProc(BOOL_TRUE);
			}

			/*�Ƿ񴴽�fast drop top ͳ���߳�*/
			if (BOOL_TRUE == SESSION_GCFG_GetTopFastDropStatEnable())
			{
				ulErr |= Session_Top_FastDrop_ThreadProc(BOOL_TRUE);
			}

			SESSION_SYNC_SendCfgToKernel();
		}
		else
		{
			ulErr = ERROR_FAILED;
		}

		/* connlmtģ����Դ��ʼ�� */
		ulErr |= CONNLMT_App_Init();
		ulErr |= SESSION_SERVICEEVENT_Init();
	}
	else
	{
		ulErr = SESSION_MESH_ClientInit();
		HOTBACKUP_Enable(BOOL_FALSE);
	}

	return ulErr;
}


/* 
Description:�Ự����ҵ��ע��
      Input:SESSION APPREG_INFO S *pstRegInfo��ע����Ϣ
     Output:SESSION APPREG_INFO_S *pstRegInfo��ע����Ϣ
*/
VOID SESSION_Register(INOUT SESSION_APPREG_INFO_S *pstRegInfo)
{
#ifdef CONFIG_DISTRIBUTED /* �ֲ�ʽ */
#ifdef CONFIG_MPU /* �ֲ�ʽ���ذ� */
	SESSION_APP_INIT_PROC(pstRegInfo,
						  _session_app_init,
						  _session_app_exit,
						  _session_app_stop,
						  _session_app_degrade,
						  _session_app_upgrade,
						  SESSION_ACL_DisconnectProc,
						  SESSION_ACL_ReconnectProc);
#else /* �ֲ�ʽ�ӿڰ� */
	SESSION_APP_INIT_PROC(pstRegInfo,
						  _session_app_init,
						  _session_app_exit,
						  NULL, 
						  NULL,
						  NULL,
						  NULL,
						  NULL);
#endif /* end of CONFIG_MPU */
#else  /* ����ʽ */
	SESSION_APP_INIT_PROC(pstRegInfo,
						  _session_app_init,
						  _session_app_exit, 
						  NULL,
						  NULL,
						  NULL,
						  SESSION_ACL_DisconnectProc,
						  SESSION_ACL_ReconnectProc);
#endif /* end of CONFIG_DISTRIBUTED */

    return;
}


/*
Description��SESSION�ػ�����������
**/
INT SESSIOND_Main(IN INT argc, IN CHAR *argv[])
{
	ULONG ulErr;

	/* ��ȡ���Ʋ��� */
	(VOID)OPT_ParseEx(argc, argv, g_astSessionStartupOpt, SESSION_OPT_OPTION_NUM);
	g_iSessionArgc = argc;
	g_ppcSessionArgv = argv;

	ulErr = _session_init();

	if (ERROR_SUCCESS == ulErr)
	{
		(VOID)SERVICE_SetStatus(SERVICE_RUNNING);
		SESSIOND_EPOLL_Wait();
	}

	_session_exit();

	return (INT)ulErr;
}

/*
Description��SESSION�ػ�����������
**/
INT main(IN INT iArgc, IN CHAR *apcArgv[])
{
	VOID *pdlHandle;
	INT(*pfSESSION_Main)(IN INT iArgc,IN CHAR*apcArgv[]);
	INT iRet = 0;

	pdlHandle = dlopen("/lib/libsession-app-ex.so", RTLD_NOW);
	if (NULL == pdlHandle)
	{
		pdlHandle= dlopen("/lib/libsession-app.so",RTLD_NOW)
	}

	if (NULL != pdlHandle)
	{
		pfSESSION_Main = dlsym(pdlHandle, "SESSIOND Main");

		iRet= pfSESSION_Main(iArgc, apcArgv),

		(VOID)dlclose(pdlHandle);
	}
	else
	{
		printf("%s\r\n", dlerror());
	}

	return iRet;
}

#endif
