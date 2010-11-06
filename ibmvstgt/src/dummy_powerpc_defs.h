/* From include/linux/of.h */

typedef u32 phandle;

struct device_node {
        const char *name;
        const char *type;
        phandle phandle;
        char    *full_name;

        struct  property *properties;
        struct  property *deadprops;    /* removed properties */
        struct  device_node *parent;
        struct  device_node *child;
        struct  device_node *sibling;
        struct  device_node *next;      /* next device of same type */
        struct  device_node *allnext;   /* next in list of all nodes */
        struct  proc_dir_entry *pde;    /* this node's proc directory */
        struct  kref kref;
        unsigned long _flags;
        void    *data;
#if defined(CONFIG_SPARC)
        char    *path_component_name;
        unsigned int unique_id;
        struct of_irq_controller *irq_trans;
#endif
};

static inline struct device_node *of_find_node_by_path(const char *path)
{
	static struct device_node rootdn;
	return &rootdn;
}
static inline const void *of_get_property(const struct device_node *node,
                                const char *name,
                                int *lenp)
{
	return NULL;
}
static inline void of_node_put(struct device_node *node)
{ }

/* From arch/powerpc/include/asm/hvcall.h */

#define H_SUCCESS       0
#define H_BUSY          1       /* Hardware busy -- retry later */

#define H_RESOURCE      -16

#define H_LONG_BUSY_START_RANGE         9900  /* Start of long busy range */
#define H_LONG_BUSY_END_RANGE           9905  /* End of long busy range */
/* Long Busy is a condition that can be returned by the firmware
 * when a call cannot be completed now, but the identical call
 * should be retried later.  This prevents calls blocking in the
 * firmware for long periods of time.  Annoyingly the firmware can return
 * a range of return codes, hinting at how long we should wait before
 * retrying.  If you don't care for the hint, the macro below is a good
 * way to check for the long_busy return codes
 */
#define H_IS_LONG_BUSY(x)  ((x >= H_LONG_BUSY_START_RANGE) \
                             && (x <= H_LONG_BUSY_END_RANGE))

#define H_REG_CRQ               0xFC
#define H_FREE_CRQ              0x100
#define H_SEND_CRQ              0x108
#define H_COPY_RDMA             0x110

static inline long plpar_hcall_norets(unsigned long opcode, ...)
{
	return 0;
}


/* From arch/powerpc/include/asm/prom.h */

/* From arch/powerpc/include/asm/vio.h */

/**
 * vio_dev - This structure is used to describe virtual I/O devices.
 *
 * @desired: set from return of driver's get_desired_dma() function
 * @entitled: bytes of IO data that has been reserved for this device.
 * @allocated: bytes of IO data currently in use by the device.
 * @allocs_failed: number of DMA failures due to insufficient entitlement.
 */
struct vio_dev {
	const char *name;
	const char *type;
	uint32_t unit_address;
	unsigned int irq;
	struct {
		size_t desired;
		size_t entitled;
		size_t allocated;
		atomic_t allocs_failed;
	} cmo;
	struct device dev;
};

struct vio_driver {
        const struct vio_device_id *id_table;
        int (*probe)(struct vio_dev *dev, const struct vio_device_id *id);
        int (*remove)(struct vio_dev *dev);
        /* A driver must have a get_desired_dma() function to
         * be loaded in a CMO environment if it uses DMA.
         */
        unsigned long (*get_desired_dma)(struct vio_dev *dev);
        struct device_driver driver;
};

static inline int vio_register_driver(struct vio_driver *drv)
{
	return 0;
}
static inline void vio_unregister_driver(struct vio_driver *drv)
{ }
static inline const void *vio_get_attribute(struct vio_dev *vdev, char *which,
                int *length)
{
	*length = 0;
	return NULL;
}
static inline struct vio_dev *vio_register_device_node(
                struct device_node *node_vdev)
{
	return NULL;
}
static inline int vio_enable_interrupts(struct vio_dev *dev)
{
        return 0;
}
static inline int vio_disable_interrupts(struct vio_dev *dev)
{
        return 0;
}
