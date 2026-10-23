/* Cppcheck-only models; never include this header in a product build.
 * The real build validates annotations and type checks. Iteration models retain
 * loop bodies, pointer traversal and sentinel conditions, without RCU semantics.
 */
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define __printf(a, b) __attribute__((format(printf, a, b)))
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define __scanf(a, b) __attribute__((format(scanf, a, b)))
#define __init
#define __exit
#define __initdata
#define __read_mostly
#define __percpu
#define __rcu
#define __user
#define __iomem
#define __force
#define __bitwise
#define __must_check
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define __packed __attribute__((packed))
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define __aligned(n) __attribute__((aligned(n)))
#define __cacheline_aligned
#define __cacheline_aligned_in_smp
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define __maybe_unused __attribute__((unused))
#define __always_inline inline
/* Define the primitive attribute model itself. */
/* checkpatch-suppress-macro PREFER_DEFINED_ATTRIBUTE_MACRO ; See the contract above. */
#define noinline __attribute__((noinline))
#define __releases(x)
#define __acquires(x)
#define __acquire(x)
#define __release(x)
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; Lockdep metadata is outside this model. */
#define __cond_lock(x, y) (y)
/* linux/bitops.h ultimately supplies the unsigned-long BIT expression. */
#define BIT(nr) (1UL << (nr))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* Preserve the typed access. Kernel size checks and memory-ordering guarantees
 * are outside this model; a bare macro name must not become READ_ONCE=1 when
 * --force explores a defined() guard in the compatibility header.
 */
/* checkpatch-suppress VOLATILE ; Model the typed kernel access. */
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))
/* checkpatch-suppress VOLATILE ; Model the typed kernel access. */
#define WRITE_ONCE(x, value) (*(volatile __typeof__(x) *)&(x) = (value))

/* Match SCST's fallback arity and arithmetic. --force must not invent an
 * object-like RHEL_RELEASE_VERSION for its #ifndef guard. Vendor release
 * codes and kernel versions still come from the captured build context.
 */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

/* Walk the possible CPU mask, retaining the real loop body and CPU indices. */
#define for_each_possible_cpu(cpu) \
	for ((cpu) = cpumask_first(cpu_possible_mask); (cpu) < nr_cpu_ids; \
	     (cpu) = cpumask_next((cpu), cpu_possible_mask))

/* Preserve the condition returned by diagnostics and the fatal BUG path.
 * Logging/once-only emission and compiler-only assertion machinery are omitted.
 */
#define WARN_ON(condition) (!!(condition))
#define WARN_ON_ONCE(condition) WARN_ON(condition)
#define BUG() __builtin_trap()
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)
/* checkpatch-suppress-macro CAMELCASE ; Use the C11 assertion keyword. */
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "BUILD_BUG_ON")

/* Typed allocations do not evaluate the object expression. Array APIs retain
 * checked multiplication, allocation flags and the actual allocator family.
 */
#define scst_cppcheck_gfp_pick(flags, ...) flags
/* checkpatch-suppress-macro SPACING ; __VA_OPT__ contributes a comma token, not a call argument. */
#define scst_cppcheck_gfp(...) scst_cppcheck_gfp_pick(__VA_OPT__(__VA_ARGS__,) GFP_KERNEL)
#define kmalloc_obj(type, ...) kmalloc(sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kzalloc_obj(type, ...) kzalloc(sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kvmalloc_obj(type, ...) kvmalloc(sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kvzalloc_obj(type, ...) kvzalloc(sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kmalloc_objs(type, count, ...) \
	kmalloc_array(count, sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kzalloc_objs(type, count, ...) \
	kcalloc(count, sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kvmalloc_objs(type, count, ...) \
	kvmalloc_array(count, sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))
#define kvzalloc_objs(type, count, ...) \
	kvcalloc(count, sizeof(type), scst_cppcheck_gfp(__VA_ARGS__))

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)
/* Keep the implicit sysfs callback references visible to whole-program checks.
 * Permission verification is a compiler check; names, modes and callbacks
 * retain the same initializer values as the kernel definitions.
 */
#define __ATTR(_name, _mode, _show, _store) \
	{ .attr = { .name = __stringify(_name), .mode = (_mode) }, \
	  .show = (_show), .store = (_store) }
#define __ATTR_RO_MODE(_name, _mode) \
	{ .attr = { .name = __stringify(_name), .mode = (_mode) }, .show = _name##_show }
#define __ATTR_RO(_name) __ATTR_RO_MODE(_name, 0444)
#define __ATTR_RW_MODE(_name, _mode) __ATTR(_name, _mode, _name##_show, _name##_store)
#define __ATTR_RW(_name) __ATTR_RW_MODE(_name, 0644)
#define __ATTR_WO(_name) __ATTR(_name, 0200, NULL, _name##_store)
#define __ATTR_NULL { .attr = { .name = NULL } }

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(head, type, member) list_entry((head)->next, type, member)
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; member is a field token, not an expression. */
#define list_next_entry(pos, member) list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry(pos, head, member) \
	for (pos = list_first_entry(head, typeof(*pos), member); \
	     &pos->member != (head); pos = list_next_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_first_entry(head, typeof(*pos), member), n = list_next_entry(pos, member); \
	     &pos->member != (head); pos = n, n = list_next_entry(n, member))
#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)
#define list_for_each_entry_rcu(pos, head, member, ...) list_for_each_entry(pos, head, member)
#define list_for_each_entry_lockless(pos, head, member) list_for_each_entry(pos, head, member)
#define list_last_entry(head, type, member) list_entry((head)->prev, type, member)
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; member is a field token, not an expression. */
#define list_prev_entry(pos, member) list_entry((pos)->member.prev, typeof(*(pos)), member)
#define list_for_each_entry_reverse(pos, head, member) \
	for (pos = list_last_entry(head, typeof(*pos), member); \
	     &pos->member != (head); pos = list_prev_entry(pos, member))
#define hlist_entry(ptr, type, member) container_of(ptr, type, member)
#define hlist_entry_safe(ptr, type, member) ((ptr) ? hlist_entry(ptr, type, member) : NULL)
#define hlist_for_each_entry(pos, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member); \
	     pos; pos = hlist_entry_safe(pos->member.next, typeof(*pos), member))
#define hlist_for_each_entry_rcu(pos, head, member, ...) hlist_for_each_entry(pos, head, member)
#define hlist_for_each_entry_safe(pos, n, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member); \
	     pos && ((n = pos->member.next), 1); pos = hlist_entry_safe(n, typeof(*pos), member))
/* Follow sg_next rather than assuming physically contiguous entries. */
#define for_each_sg(sglist, sg, nr, i) \
	for (i = 0, sg = (sglist); i < (nr); i++, sg = sg_next(sg))
#define KERN_EMERG ""
#define KERN_ALERT ""
#define KERN_CRIT ""
#define KERN_ERR ""
#define KERN_WARNING ""
#define KERN_NOTICE ""
#define KERN_INFO ""
#define KERN_DEBUG ""
#define KERN_CONT ""

/* Match Linux kconfig.h: undefined and module-valued options are distinct. */
#define __ARG_PLACEHOLDER_1 0,
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; The first argument is deliberately discarded. */
#define __take_second_arg(__ignored, val, ...) val
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) __is_defined(option##_MODULE)
/* checkpatch-suppress-macro IS_ENABLED_CONFIG ; Define the configuration helper itself. */
#define IS_ENABLED(option) (IS_BUILTIN(option) || IS_MODULE(option))
#define IS_REACHABLE(option) (IS_BUILTIN(option) || (IS_MODULE(option) && __is_defined(MODULE)))

#define btree_for_each_safe64(head, key, val) \
	for (val = btree_last64(head, &(key)); val; val = btree_get_prev64(head, &(key)))
#define btree_for_each_safe32(head, key, val) \
	for (val = btree_last32(head, &(key)); val; val = btree_get_prev32(head, &(key)))

/* QLogic trace assignments remain executable code in the analysis model.
 * String storage and registration belong to the kernel tracing runtime.
 */
#define TP_PROTO(...) __VA_ARGS__
#define TP_ARGS(...) __VA_ARGS__
#define TP_STRUCT__entry(...) __VA_ARGS__
#define TP_fast_assign(...) __VA_ARGS__
#define TP_printk(...) cppcheck_trace_print(__VA_ARGS__)
/* checkpatch-suppress-macro TRAILING_SEMICOLON ; Expand to a complete field declaration. */
#define __field(type, name) type name;
/* checkpatch-suppress-macro TRAILING_SEMICOLON ; Expand to a complete field declaration. */
#define __array(type, name, count) type name[count];
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name is a field declarator. */
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; Tracing storage allocation is outside this model. */
/* checkpatch-suppress-macro TRAILING_SEMICOLON ; Expand to a complete field declaration. */
#define __dynamic_array(type, name, count) type *name;
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name is a field declarator. */
/* Storage is assigned by the trace assignment macro. */
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; See the contract above. */
/* checkpatch-suppress-macro TRAILING_SEMICOLON ; Expand to a complete field declaration. */
#define __string(name, source) const char *name;
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name is a field declarator. */
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; Formatting is modeled in the trace assignment. */
/* checkpatch-suppress-macro TRAILING_SEMICOLON ; Expand to a complete field declaration. */
#define __vstring(name, fmt, va) const char *name;
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name must remain a field token after ->. */
#define __assign_str(name, ...) (__entry->name = name)
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name must remain a field token after ->. */
#define __assign_vstr(name, fmt, va) (__entry->name = cppcheck_trace_vstring(fmt, va))
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; name must remain a field token after ->. */
#define __get_str(name) (__entry->name)
/* proto declares arguments; DEFINE_EVENT forwards them. */
/* checkpatch-suppress-macro MACRO_ARG_UNUSED ; See the contract above. */
#define DECLARE_EVENT_CLASS(name, proto, args, fields, assign, print) \
	struct cppcheck_event_##name { fields }; \
	static void cppcheck_assign_##name(proto) \
	{ \
		struct cppcheck_event_##name entry; \
		struct cppcheck_event_##name *__entry = &entry; \
		assign; \
		print; \
	}
#define DEFINE_EVENT(template, name, proto, args) \
	static void trace_##name(proto) { cppcheck_assign_##template(args); }
