#include <linux/dma-mapping.h>

/* <rdma/ib_verbs.h> */
#ifndef HAVE_IB_DMA_MAP_OPS
static inline int ib_dma_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_mapping_error(dev->dma_device, dma_addr);
}

static inline u64 ib_dma_map_single(struct ib_device *dev,
				    void *cpu_addr, size_t size,
				    enum dma_data_direction direction)
{
	return dma_map_single(dev->dma_device, cpu_addr, size, direction);
}

static inline void ib_dma_unmap_single(struct ib_device *dev,
				       u64 addr, size_t size,
				       enum dma_data_direction direction)
{
	dma_unmap_single(dev->dma_device, addr, size, direction);
}

static inline u64 ib_dma_map_single_attrs(struct ib_device *dev,
					  void *cpu_addr, size_t size,
					  enum dma_data_direction direction,
					  unsigned long dma_attrs)
{
	return dma_map_single_attrs(dev->dma_device, cpu_addr, size,
				    direction, dma_attrs);
}

static inline void ib_dma_unmap_single_attrs(struct ib_device *dev,
					     u64 addr, size_t size,
					     enum dma_data_direction direction,
					     unsigned long dma_attrs)
{
	return dma_unmap_single_attrs(dev->dma_device, addr, size,
				      direction, dma_attrs);
}

static inline u64 ib_dma_map_page(struct ib_device *dev,
				  struct page *page,
				  unsigned long offset,
				  size_t size,
				  enum dma_data_direction direction)
{
	return dma_map_page(dev->dma_device, page, offset, size, direction);
}

static inline void ib_dma_unmap_page(struct ib_device *dev,
				     u64 addr, size_t size,
				     enum dma_data_direction direction)
{
	dma_unmap_page(dev->dma_device, addr, size, direction);
}

static inline int ib_dma_map_sg(struct ib_device *dev,
				struct scatterlist *sg, int nents,
				enum dma_data_direction direction)
{
	return dma_map_sg(dev->dma_device, sg, nents, direction);
}

static inline void ib_dma_unmap_sg(struct ib_device *dev,
				   struct scatterlist *sg, int nents,
				   enum dma_data_direction direction)
{
	dma_unmap_sg(dev->dma_device, sg, nents, direction);
}

static inline int ib_dma_map_sg_attrs(struct ib_device *dev,
				      struct scatterlist *sg, int nents,
				      enum dma_data_direction direction,
				      unsigned long dma_attrs)
{
	return dma_map_sg_attrs(dev->dma_device, sg, nents, direction,
				dma_attrs);
}

static inline void ib_dma_unmap_sg_attrs(struct ib_device *dev,
					 struct scatterlist *sg, int nents,
					 enum dma_data_direction direction,
					 unsigned long dma_attrs)
{
	dma_unmap_sg_attrs(dev->dma_device, sg, nents, direction, dma_attrs);
}

static inline u64 ib_sg_dma_address(struct ib_device *dev,
				    struct scatterlist *sg)
{
	return sg_dma_address(sg);
}

static inline unsigned int ib_sg_dma_len(struct ib_device *dev,
					 struct scatterlist *sg)
{
	return sg_dma_len(sg);
}

static inline void ib_dma_sync_single_for_cpu(struct ib_device *dev,
					      u64 addr,
					      size_t size,
					      enum dma_data_direction dir)
{
	dma_sync_single_for_cpu(dev->dma_device, addr, size, dir);
}

static inline void ib_dma_sync_single_for_device(struct ib_device *dev,
						 u64 addr,
						 size_t size,
						 enum dma_data_direction dir)
{
	dma_sync_single_for_device(dev->dma_device, addr, size, dir);
}

static inline void *ib_dma_alloc_coherent(struct ib_device *dev,
                                          size_t size,
                                          u64 *dma_handle,
                                          gfp_t flag)
{
	dma_addr_t handle;
	void *ret;

	ret = dma_alloc_coherent(dev->dma_device, size, &handle, flag);
	*dma_handle = handle;
	return ret;
}

static inline void ib_dma_free_coherent(struct ib_device *dev,
					size_t size, void *cpu_addr,
					u64 dma_handle)
{
	dma_free_coherent(dev->dma_device, size, cpu_addr, dma_handle);
}
#endif
