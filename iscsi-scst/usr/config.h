#ifndef CONFIG_H
#define CONFIG_H

struct config_operations {
	int (*init) (char *, char **, int *);
	int (*default_load) (char *);
	int (*target_add) (u32 *, char *);
	int (*target_stop) (u32);
	int (*target_del) (u32);
	int (*param_set) (u32, u64, int, u32, struct iscsi_param *);
	int (*account_add) (u32, int, char *, char *);
	int (*account_del) (u32, int, char *);
	int (*account_query) (u32, int, char *, char *);
	int (*initiator_access) (u32, int);
};

extern struct config_operations *cops;

#endif
