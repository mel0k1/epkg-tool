/* freestanding shim: epkg's main.c includes <stdio.h> but needs nothing
 * beyond NULL; gcc provides stdint.h/stddef.h/stdarg.h itself. */
#ifndef EPK_SHIM_STDIO_H
#define EPK_SHIM_STDIO_H

#ifndef NULL
#define NULL ((void *)0)
#endif

#endif /* EPK_SHIM_STDIO_H */
