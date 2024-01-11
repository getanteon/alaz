
struct go_interface {
    __s64 type;
    void* ptr;
};

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GOROUTINE(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64) 
/* arm64 provides struct user_pt_regs instead of struct pt_regs to userspace */
#define GO_PARAM1(x) (((struct user_pt_regs *)(x))->regs[0])
#define GO_PARAM2(x) (((struct user_pt_regs *)(x))->regs[1])
#define GO_PARAM3(x) (((struct user_pt_regs *)(x))->regs[2])
#define GOROUTINE(x) (((struct user_pt_regs *)(x))->regs[28])
#endif