#ifdef RTE_BACKTRACE
#include <execinfo.h>
#endif
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <rte_log.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_eal.h>

#define BACKTRACE_SIZE 256

/* dump the stack of the calling core */
void flow_dump_stack(void *data)
{
	void *func[BACKTRACE_SIZE];
	char **symb = NULL;
	int size;

	size = backtrace(func, BACKTRACE_SIZE);
	symb = backtrace_symbols(func, size);

	if (symb == NULL)
		return;

    printf("********************stack start**********************\n");
    printf("data : %p\n", data);
	while (size > 0) {
		printf("%d: [%s]\n", size, symb[size - 1]);
		size --;
	}
    printf("********************stack end**********************\n");

	free(symb);
}

